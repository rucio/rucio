/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014
*/

package rucioudfs;
import java.io.IOException;
import java.security.MessageDigest;
import org.apache.pig.EvalFunc;
import org.apache.pig.data.Tuple;
import org.apache.pig.impl.util.WrappedIOException;

public class GETPATH extends EvalFunc<String>
{
    public String exec(Tuple input) throws IOException {
        if (input == null || input.size() == 0)
            return null;
        try{
            String scope = (String)input.get(0);
            String name = (String)input.get(1);
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(scope.concat(":").concat(name).getBytes());
            byte[] digest = md.digest();

            String md5_1 = String.format("%02x", digest[0] & 0xff);
            String md5_2 = String.format("%02x", digest[1] & 0xff);

            String corrected_scope = scope;
            if (corrected_scope.startsWith("user") || corrected_scope.startsWith("group")) {
                corrected_scope.replace(".", "/");
            }

            return corrected_scope.concat("/").concat(md5_1).concat("/").concat(md5_2).concat("/").concat(name);
        }catch(Exception e){
            throw WrappedIOException.wrap("Caught exception processing input row ", e);
        }
    }
}
