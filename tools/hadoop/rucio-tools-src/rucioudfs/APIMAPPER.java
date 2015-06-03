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
      if (uri.matches(".*?/dids/(.+?)(/?\\?.*)?$")) {
        return "dids.Scope";
      } else if (uri.matches(".*?/dids/(.+?)/guid$")) {
        return "dids.GUIDLookup";
      } else if (uri.matches(".*?/dids/(.+?)/dids/search(/?\\?.*)?$")) {
        return "dids.Search";
      } else if (uri.matches(".*?/dids/(.+?)/(.+?)//?files(/?\\?.*)?$")) {
        return "dids.Files";
      } else if (uri.matches(".*?/dids/(.+?)/(.+?)//?dids(/?\\?.*)?$")) {
        return "dids.Attachement";
      } else if (uri.matches(".*?/dids/attachments$")) {
        return "dids.Attachement";
      } else if (uri.matches(".*?/dids/(.+?)/(.+?)//?meta(/.+?)?(/?\\?.*)?$")) {
        return "dids.Meta";
      } else if (uri.matches(".*?/dids/(.+?)/(.+?)(/status)?(/?\\?.*)?$")) {
        return "dids.DIDs";
      } else if (uri.matches(".*?/dids/(.+?)/(.+?)//?rules(/?\\?.*)?$")) {
        return "dids.Rules";
      } else if (uri.matches(".*?/dids/(.+?)/(.+?)/parents(/?\\?.*)?$")) {
        return "dids.Parents";
      } else if (uri.matches(".*?/dids/(.+?)/(.+?)/associated_rules$(/?\\?.*)?")) {
        return "dids.AssociatedRules";
      } else if (uri.matches(".*?/dids(/?\\?.*)?$")) {
        return "dids.BulkDIDS";
      }


      // replicas
      if (uri.matches(".*?/replicas/list(/?\\?.*)?$")) {
        return "replicas.ListReplicas";
      } else if (uri.matches(".*?/replicas(/.+?){0,2}?(/?\\?.*)?$")) {
        return "replicas.Replicas";
      } else if (uri.matches(".*?/replicas/(.*)?datasets$")) {
        return "replicas.ListDatasetReplicas";
      } else if (uri.matches(".*?/replicas/bad(/?\\?.*)?$")) {
        return "replicas.BadReplicas";
      } else if (uri.matches(".*?/replicas/suspicious(/?\\?.*)?$")) {
        return "replicas.SuspiciousReplicas";
      } else if (uri.matches(".*?/replicas/dids(/?\\?.*)?$")) {
        return "replicas.ReplicasDIDs";
      }
      // accounts:
      if (uri.matches(".*?/accounts/(.+?)/attr(.+?)?(/?\\?.*)?$")) {
        return "account.Attributes";
      } else if (uri.matches(".*?/accounts/(.+?)/scopes(/.+?)?(/?\\?.*)?$")) {
        return "account.Scopes";
      } else if (uri.matches(".*?/accounts/(.+?)/identities(/?\\?.*)?$")) {
        return "account.Identities";
      } else if (uri.matches(".*?/accounts/(.+?)/limits(/.+?)?(/?\\?.*)?$")) {
        return "account.AccountLimits";
      } else if (uri.matches(".*?/accounts/(.+?)/rules(/?\\?.*)?$")) {
        return "account.Rules";
      } else if (uri.matches(".*?/accounts/(.+?)/usage(/?\\?.*)?$")) {
        return "account.Usage1";
      } else if (uri.matches(".*?/accounts/(.+?)/usage/(.+?)(/?\\?.*)?$")) {
        return "account.Usage2";
      } else if (uri.matches(".*?/accounts/(.+?)(/?\\?.*)?$")) {
        return "account.AccountParameter";
      } else if (uri.matches(".*?/accounts(/?\\?.*)?$")) {
        return "account.Account";
      }

      // account_limits:
      if (uri.matches(".*?/accountlimits/(.+?)/(.+?)(/?\\?.*)?$")) {
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
      if (uri.matches(".*?/config/(.+?)/(.+?)/(.+?)(/?\\?.*)?$")) {
        return "config.OptionSet";
      } else if (uri.matches(".*?/config/(.+?)/(.+?)(/?\\?.*)?$")) {
        return "config.OptionGetDel";
      } else if (uri.matches(".*?/config/(.+?)(/?\\?.*)?$")) {
        return "config.Selection";
      } else if (uri.matches(".*?/config$")) {
        return "config.Config";
      }

      // identity
      if (uri.matches(".*?/identities/(.+?)/userpass(/?\\?.*)?")) {
        return "identity.UserPass";
      } else if (uri.matches(".*?/identities/(.+?)/x509(/?\\?.*)?")) {
        return "identity.x509";
      } else if (uri.matches(".*?/identities/(.+?)/gss(/?\\?.*)?")) {
        return "identity.GSS";
      }

      // lock
      if (uri.matches(".*?/locks/(.+?)/(.+?)(/?\\?.*)?$")) {
        return "lock.LockByScopeName";
      } else if (uri.matches(".*?/locks/(.+?)(/?\\?.*)?$")) {
        return "lock.LockByRSE";
      }

      // meta
      if (uri.matches(".*?/meta/(.+?)/(.+?)?(/?\\?.*)?$")) {
        return "meta.Values";
      } else if (uri.matches(".*?/meta/(.+?)?(/?\\?.*)?$")) {
        return "meta.Meta";
      }

      // ping
      if (uri.matches(".*?/ping(/?\\?.*)?$")) {
        return "ping.Ping";
      }

      // redirect
      if (uri.matches(".*?/redirect/(.+?)/(.+?)(/?\\?.*)?$")) {
        return "redirect.Redirector";
      }

      // request
      if (uri.matches(".*?/requests/(.+?)/(.+?)/(.+?)(/?\\?.*)?$")) {
        return "request.RequestGet";
      }

      // rse
      if (uri.matches(".*?/rses/(.+?)/attr/(.+?)?(/?\\?.*)?$")) {
        return "rse.Attributes";
      } else if (uri.matches(".*?/rses/(.+?)/protocol(/.+?){0,3}(/?\\?.*)?$")) {
        return "rse.Protocol";
      } else if (uri.matches(".*?/rses/(.+?)/protocols(/?\\?.*)?$")) {
        return "rse.Protocols";
      } else if (uri.matches(".*?/rses/(.+?)/usage(/?\\?.*)?$")) {
        return "rse.Usage ";
      } else if (uri.matches(".*?/rses/(.+?)/usage/history(/?\\?.*)?$")) {
        return "rse.UsageHistory";
      } else if (uri.matches(".*?/rses/(.+?)/limits(/?\\?.*)?$")) {
        return "rse.Limits";
      } else if (uri.matches(".*?/rses/(.+?)(/?\\?.*)?$")) {
        return "rse.RSE";
      } else if (uri.matches(".*?/rses/?(/?\\?.*)?$")) {
        return "rse.RSEs";
      }

      // rule
      if (uri.matches(".*?/rules/(.+?)/locks(/?\\?.*)?$")) {
        return "rule.ReplicaLocks";
      } else if (uri.matches(".*?/rules/(.+?)/reduce(/?\\?.*)?$")) {
        return "rule.ReduceRule";
      } else if (uri.matches(".*?/rules/(.+?)?(/?\\?.*)?$")) {
        return "rule.Rule";
      }

      // scope
      if (uri.matches(".*?/scopes/((.+?)/scopes)?(/?\\?.*)?$")) {
        return "scopes.Scopes";
      } else if (uri.matches(".*?/scopes/(.+?)/limits(/?\\?.*)?$")) {
        return "scopes.AccountLimits";
      } else if (uri.matches(".*?/scopes/(.+?)(/?\\?.*)?$")) {
        return "scopes.AccountParameter";
      }

      // subscription
      if (uri.matches(".*?/subscriptions/Id/(.+?)(/?\\?.*)?")) {
        return "subscription.SubscriptionId";
      } else if (uri.matches(".*?/subscriptions/(.+?/){1,2}rules/states(/?\\?.*)?")) {
        return "subscription.States";
      } else if (uri.matches(".*?/subscriptions/(.+?)/(.+?)/rules(/?\\?.*)?")) {
        return "subscription.Rules";
      } else if (uri.matches(".*?/subscriptions/(.+?)(/.+?)?(/?\\?.*)?$")) {
        return "subscription.Subscription";
      }

      // trace
      if (uri.matches(".*?/traces/")) {
        return "trace.Trace";
      }

      // Unmacthed
      return "error.UnknownRequest: " + uri;
    } catch(Exception e) {
      throw WrappedIOException.wrap("Caught exception processing input row: ", e);
    }
  }
}
