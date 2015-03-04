/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Ralph Vigne <ralph.vigne@cern.cg>, 2015
*/

package rucioudfs;
import java.io.IOException;
import java.security.MessageDigest;
import org.apache.pig.EvalFunc;
import org.apache.pig.data.Tuple;
import org.apache.pig.impl.util.WrappedIOException;


public class APIMAPPER extends EvalFunc<String> {
  public String exec(Tuple input) throws IOException {
    if (input == null || input.size() == 0)
      return null;

    try {
      String uri = (String)input.get(0);

      // DIDs
      if (uri.matches(".*?/dids/([\\w.-]+)(/?\\?.*)?$")) {
        return "dids.Scope";
      } else if (uri.matches(".*?/dids/([\\w.-]+)/guid$")) {
        return "dids.GUIDLookup";
      } else if (uri.matches(".*?/dids/([\\w.-]+)/dids/search(/?\\?.*)?$")) {
        return "dids.Search";
      } else if (uri.matches(".*?/dids/([\\w.-]+)/([\\w.-]+)//?files(/?\\?.*)?$")) {
        return "dids.Files";
      } else if (uri.matches(".*?/dids/([\\w.-]+)/([\\w.-]+)//?dids(/?\\?.*)?$")) {
        return "dids.Attachement";
      } else if (uri.matches(".*?/dids/attachments$")) {
        return "dids.Attachement";
      } else if (uri.matches(".*?/dids/([\\w.-]+)/([\\w.-]+)//?meta(/[\\w.-]+)?(/?\\?.*)?$")) {
        return "dids.Meta";
      } else if (uri.matches(".*?/dids/([\\w.-]+?)/([\\w.-]+?)(/status)?(/?\\?.*)?$")) {
        return "dids.DIDs";
      } else if (uri.matches(".*?/dids/([\\w.-]+)/([\\w.-]+)//?rules(/?\\?.*)?$")) {
        return "dids.Rules";
      } else if (uri.matches(".*?/dids/([\\w.-]+)/([\\w.-]+)/parents(/?\\?.*)?$")) {
        return "dids.Parents";
      } else if (uri.matches(".*?/dids/([\\w.-]+)/([\\w.-]+)/associated_rules$(/?\\?.*)?")) {
        return "dids.AssociatedRules";
      } else if (uri.matches(".*?/dids(/?\\?.*)?$")) {
        return "dids.BulkDIDS";
      }


      // replicas
      if (uri.matches(".*?/replicas/list(/?\\?.*)?$")) {
        return "replicas.ListReplicas";
      } else if (uri.matches(".*?/replicas(/[\\w.-]+){0,2}?(/?\\?.*)?$")) {
        return "replicas.Replicas";
      } else if (uri.matches(".*?/replicas/bad(/?\\?.*)?$")) {
        return "replicas.BadReplicas";
      } else if (uri.matches(".*?/replicas/suspicious(/?\\?.*)?$")) {
        return "replicas.SuspiciousReplicas";
      } else if (uri.matches(".*?/replicas/dids(/?\\?.*)?$")) {
        return "replicas.ReplicasDIDs";
      }
      // accounts:
      if (uri.matches(".*?/accounts/([\\w.-]+)/attr([\\w.-]+)?(/?\\?.*)?$")) {
        return "account.Attributes";
      } else if (uri.matches(".*?/accounts/([\\w.-]+)/scopes(/[\\w.-]+)?(/?\\?.*)?$")) {
        return "account.Scopes";
      } else if (uri.matches(".*?/accounts/([\\w.-]+)/identities(/?\\?.*)?$")) {
        return "account.Identities";
      } else if (uri.matches(".*?/accounts/([\\w.-]+)/limits(/[\\w.-]+)?(/?\\?.*)?$")) {
        return "account.AccountLimits";
      } else if (uri.matches(".*?/accounts/rules(/?\\?.*)?$")) {
        return "account.Rules";
      } else if (uri.matches(".*?/accounts/usage(/?\\?.*)?$")) {
        return "account.Usage1";
      } else if (uri.matches(".*?/accounts/usage/([\\w.-]+)(/?\\?.*)?$")) {
        return "account.Usage2";
      } else if (uri.matches(".*?/accounts/([\\w.-]+)(/?\\?.*)?$")) {
        return "account.AccountParameter";
      } else if (uri.matches(".*?/accounts(/?\\?.*)?$")) {
        return "account.Account";
      }

      // account_limits:
      if (uri.matches(".*?/accountlimits/([\\w.-]+)/([\\w.-]+)(/?\\?.*)?$")) {
        return "account_limits.AccountLimits";
      }

      // authentication:
      if (uri.matches(".*?/auth/userpass$")) {
        return "authentication.UserPass";
      } else if (uri.matches(".*?/auth/gss(/?\\?.*)?$")) {
        return "authentication.GSS";
      } else if (uri.matches(".*?/auth/x509(_proxy)?(/?\\?.*)?$")) {
        return "authentication.x509";
      } else if (uri.matches(".*?/auth/validate(/?\\?.*)?$")) {
        return "authentication.Validate";
      }

      // config
      if (uri.matches(".*?/config/([\\w.-]+)/([\\w.-]+)/([\\w.-]+)(/?\\?.*)?$")) {
        return "config.OptionSet";
      } else if (uri.matches(".*?/config/([\\w.-]+)/([\\w.-]+)(/?\\?.*)?$")) {
        return "config.OptionGetDel";
      } else if (uri.matches(".*?/config/([\\w.-]+)(/?\\?.*)?$")) {
        return "config.Selection";
      } else if (uri.matches(".*?/config$")) {
        return "config.Config";
      }

      // identity
      if (uri.matches(".*?/identities/([\\w.-]+)/userpass(/?\\?.*)?")) {
        return "identity.UserPass";
      } else if (uri.matches(".*?/identities/([\\w.-]+)/x509(/?\\?.*)?")) {
        return "identity.x509";
      } else if (uri.matches(".*?/identities/([\\w.-]+)/gss(/?\\?.*)?")) {
        return "identity.GSS";
      }

      // lock
      if (uri.matches(".*?/locks/([\\w.-]+)/([\\w.-]+)(/?\\?.*)?$")) {
        return "lock.LockByScopeName";
      } else if (uri.matches(".*?/locks/([\\w.-]+)(/?\\?.*)?$")) {
        return "lock.LockByRSE";
      }

      // meta
      if (uri.matches(".*?/meta/([\\w.-]+)/([\\w.-]+)?(/?\\?.*)?$")) {
        return "meta.Values";
      } else if (uri.matches(".*?/meta/([\\w.-]+)?(/?\\?.*)?$")) {
        return "meta.Meta";
      }

      // ping
      if (uri.matches(".*?/ping(/?\\?.*)?$")) {
        return "ping.Ping";
      }

      // redirect
      if (uri.matches(".*?/redirect/([\\w.-]+)/([\\w.-]+)(/?\\?.*)?$")) {
        return "redirect.Redirector";
      }

      // request
      if (uri.matches(".*?/requests/([\\w.-]+)/([\\w.-]+)/([\\w.-]+)(/?\\?.*)?$")) {
        return "request.RequestGet";
      }

      // rse
      if (uri.matches(".*?/rses/([\\w.-]+)/attr/([\\w.-]+)?(/?\\?.*)?$")) {
        return "rse.Attributes";
      } else if (uri.matches(".*?/rses/([\\w.-]+)/protocol(/[\\w.-]+){0,3}(/?\\?.*)?$")) {
        return "rse.Protocol";
      } else if (uri.matches(".*?/rses/([\\w.-]+)/protocols(/?\\?.*)?$")) {
        return "rse.Protocols";
      } else if (uri.matches(".*?/rses/([\\w.-]+)/usage(/?\\?.*)?$")) {
        return "rse.Usage ";
      } else if (uri.matches(".*?/rses/([\\w.-]+)/usage/history(/?\\?.*)?$")) {
        return "rse.UsageHistory";
      } else if (uri.matches(".*?/rses/([\\w.-]+)/limits(/?\\?.*)?$")) {
        return "rse.Limits";
      } else if (uri.matches(".*?/rses/([\\w.-]+)(/?\\?.*)?$")) {
        return "rse.RSE";
      } else if (uri.matches(".*?/rses/?(/?\\?.*)?$")) {
        return "rse.RSEs";
      }

      // rule
      if (uri.matches(".*?/rules/([\\w.-]+)/locks(/?\\?.*)?$")) {
        return "rule.ReplicaLocks";
      } else if (uri.matches(".*?/rules/([\\w.-]+)/reduce(/?\\?.*)?$")) {
        return "rule.ReduceRule";
      } else if (uri.matches(".*?/rules/([\\w.-]+)?(/?\\?.*)?$")) {
        return "rule.Rule";
      }

      // scope
      if (uri.matches(".*?/scopes/(([\\w.-]+)/scopes)?(/?\\?.*)?$")) {
        return "scopes.Scopes";
      } else if (uri.matches(".*?/scopes/([\\w.-]+)/limits(/?\\?.*)?$")) {
        return "scopes.AccountLimits";
      } else if (uri.matches(".*?/scopes/([\\w.-]+)(/?\\?.*)?$")) {
        return "scopes.AccountParameter";
      }

      // subscription
      if (uri.matches(".*?/subscriptions/Id/([\\w.-]+)(/?\\?.*)?")) {
        return "subscription.SubscriptionId";
      } else if (uri.matches(".*?/subscriptions/([\\w.-]+){1,2}/Rules/States(/?\\?.*)?")) {
        return "subscription.States";
      } else if (uri.matches(".*?/subscriptions/([\\w.-]+)/([\\w.-]+)/Rules(/?\\?.*)?")) {
        return "subscription.Rules";
      } else if (uri.matches(".*?/subscriptions/([\\w.-]+)?(/[\\w.-]+)?(/?\\?.*)?$")) {
        return "subscription.Subscription";
      }

      // trace
      if (uri.matches(".*?/traces/")) {
        return "trace.Trace";
      }

      // Unmacthed
      return "error.MalformedRequest: " + uri;
    } catch(Exception e) {
      throw WrappedIOException.wrap("Caught exception processing input row: ", e);
    }
  }
}
