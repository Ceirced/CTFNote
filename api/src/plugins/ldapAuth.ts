import { makeExtendSchemaPlugin, gql } from "graphile-utils";
import * as ldapAuthentication from "ldap-authentication";
import * as jwt from "jsonwebtoken";
import config from "../config";
import { Context } from "./uploadLogo";

interface LdapUserInfo {
  uid: string;
  cn: string;
  mail?: string;
  memberOf?: string[];
}

async function authenticateWithLdap(username: string, password: string): Promise<LdapUserInfo | null> {
  if (!config.ldap.enabled) {
    throw new Error("LDAP authentication is not enabled");
  }

  console.log("LDAP authentication attempt for user:", username);
  console.log("LDAP URL:", config.ldap.url);

  try {
    const options = {
      ldapOpts: {
        url: config.ldap.url,
      },
      adminDn: config.ldap.bindDN,
      adminPassword: config.ldap.bindPassword,
      userSearchBase: config.ldap.searchBase,
      usernameAttribute: config.ldap.usernameAttribute,
      username: username,
      userPassword: password,
    };

    console.log("LDAP options:", JSON.stringify(options, null, 2));

    const user = await ldapAuthentication.authenticate(options);
    
    if (user) {
      console.log("LDAP authentication successful for user:", username);
      return {
        uid: user[config.ldap.usernameAttribute] || username,
        cn: user.cn || user.displayName || username,
        mail: user[config.ldap.emailAttribute],
        memberOf: user[config.ldap.groupAttribute] || [],
      };
    }
    
    console.log("LDAP authentication failed for user:", username);
    return null;
  } catch (error) {
    console.error("LDAP authentication error:", error);
    return null;
  }
}

function getUserRoleFromGroups(memberOf: string[]): string {
  // Check admin groups first
  if (config.ldap.adminGroups.some(group => 
    memberOf.some(userGroup => userGroup.toLowerCase().includes(group.toLowerCase()))
  )) {
    return "user_admin";
  }
  
  // Check manager groups
  if (config.ldap.managerGroups.some(group => 
    memberOf.some(userGroup => userGroup.toLowerCase().includes(group.toLowerCase()))
  )) {
    return "user_manager";
  }
  
  // Check user groups
  if (config.ldap.userGroups.some(group => 
    memberOf.some(userGroup => userGroup.toLowerCase().includes(group.toLowerCase()))
  )) {
    return "user_member";
  }
  
  // Default role
  return "user_guest";
}

export default makeExtendSchemaPlugin(() => {
  console.log("LDAP Plugin initialization - LDAP enabled:", config.ldap.enabled);
  
  return {
    typeDefs: gql`
      extend type Query {
        ldapAuthEnabled: Boolean
      }
      ${config.ldap.enabled ? `
        type LdapAuthPayload {
          jwt: String
        }
        extend type Mutation {
          authenticateWithLdap(username: String!, password: String!): LdapAuthPayload
        }
      ` : ''}
    `,
    resolvers: {
      Query: {
        ldapAuthEnabled: () => config.ldap.enabled,
      },
      ...(config.ldap.enabled ? {
        Mutation: {
          authenticateWithLdap: async (_parent: unknown, args: { username: string; password: string }, context: Context) => {
            console.log("LDAP authenticateWithLdap resolver called for user:", args.username);
            const { username, password } = args;
            
            if (!config.ldap.enabled) {
              throw new Error("LDAP authentication is not enabled");
            }

            // Authenticate with LDAP
            const ldapUser = await authenticateWithLdap(username, password);
            
            if (!ldapUser) {
              throw new Error("Invalid LDAP credentials");
            }

            // Determine user role based on LDAP groups
            const userRole = getUserRoleFromGroups(ldapUser.memberOf || []);
            console.log("Determined user role:", userRole);

            try {
              // Use the database function to handle user creation/update
              console.log("Calling database function with:", { username, userRole, ldapData: JSON.stringify(ldapUser) });
              const result = await context.pgClient.query(
                `SELECT (ctfnote.login_ldap($1, $2, $3)).*`,
                [username, userRole, JSON.stringify(ldapUser)]
              );

              console.log("Database query result:", result);
              console.log("Result rows:", result.rows);
              
              const jwtRow = result.rows[0];
              console.log("JWT row:", jwtRow);

              if (!jwtRow || !jwtRow.user_id) {
                console.error("Database function returned no JWT data");
                throw new Error("Database function failed to generate token");
              }

              // Create JWT payload from the database result
              const jwtPayload = {
                user_id: parseInt(jwtRow.user_id),
                role: jwtRow.role,
                exp: parseInt(jwtRow.exp),
                aud: "postgraphile" // Add the required audience
              };
              console.log("JWT payload:", jwtPayload);

              // Sign the JWT token using the same secret as PostGraphile
              const jwtSecret = config.env === "development" ? "DEV" : config.sessionSecret;
              const signedJwt = jwt.sign(jwtPayload, jwtSecret);
              console.log("Signed JWT token:", signedJwt);

              return {
                jwt: signedJwt,
              };
            } catch (dbError) {
              console.error("Database error during LDAP login:", dbError);
              throw new Error("Failed to process LDAP login");
            }
          },
        },
      } : {}),
    },
  };
});
