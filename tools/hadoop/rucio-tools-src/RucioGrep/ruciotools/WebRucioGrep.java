/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Ralph Vigne <ralph.vigne@cern.ch>, 2015
*/

package ruciotools;


import ruciotools.Grep;

import java.io.IOException;
import java.util.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;


import java.security.PrivilegedExceptionAction;


import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FSDataInputStream;


/**
 * Servlet implementation class ReadFromHdfs
 */
public class WebRucioGrep extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public WebRucioGrep() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		final PrintWriter out = response.getWriter();

                Enumeration<String> parameterNames = request.getParameterNames();
		List<String> params = new ArrayList<String>();
        	while (parameterNames.hasMoreElements()) {
            		String paramName = parameterNames.nextElement();
			for(String v: request.getParameterValues(paramName)) {
				params.add("-"+paramName);
				params.add(v);
			}
			
        	}
		final String [] args = new String[params.size()];
		params.toArray(args);

		FileSystem fs = DistributedFileSystem.get(new Configuration());
		FSDataOutputStream of1 = fs.create(new Path ("/user/rucio01/log/test-MR-before.ralph"));
		of1.write(new String("ralph").getBytes());
		of1.close();

System.out.println("--------------status---:"	+ UserGroupInformation.isLoginKeytabBased());
System.out.println("--------------current user---:" + UserGroupInformation.getCurrentUser());
		UserGroupInformation ugi = UserGroupInformation.getCurrentUser();
		boolean isKeyTab = false; //ugi.isFromKeytab();
		if (isKeyTab) {
			ugi.checkTGTAndReloginFromKeytab();
		} else {
			UserGroupInformation.loginUserFromKeytab("rucio01", "/etc/hadoop/conf/rucio01.keytab");
			isKeyTab = UserGroupInformation.isLoginKeytabBased();
			if (isKeyTab) {
				ugi = UserGroupInformation.getCurrentUser();
			}
		}
System.out.println("---------AFTER LOGIN-----:");
System.out.println("--------------status---:"	+ UserGroupInformation.isLoginKeytabBased());
System.out.println("--------------current user---:" + UserGroupInformation.getCurrentUser());

		//FileSystem fs = DistributedFileSystem.get(new Configuration());
		FSDataOutputStream of = fs.create(new Path ("/user/rucio01/log/test-MR-outer.ralph"));
		of.write(new String("ralph").getBytes());
		of.close();

try{
ugi.doAs(new PrivilegedExceptionAction<Void>() {
    public Void run() throws Exception {

		FileSystem fs = DistributedFileSystem.get(new Configuration());
		FSDataOutputStream of = fs.create(new Path ("/user/rucio01/log/test-MR-inner.ralph"));
		of.write(new String("ralph").getBytes());
		of.close();

		// Verify input parameters
  		Map<String, Object> settings = Grep.parseCommandLineArguments(args);
    		if ((Boolean)settings.get("printUsage")) {
			out.println((String)settings.get("errorMessage"));
			out.println(Grep.printUsage());
			return null;
		}

		// Derive tmp dir for job output
		settings.put("tempDir", new Path("rucio-grep-"+Integer.toString(new Random().nextInt(Integer.MAX_VALUE))));

		// Execute MR job
		try {
			if (!Grep.runJob(settings)) {
				out.println("Something went wrong :-(\n");
				out.println("Hints: (1) do not redirect stderr to /dev/null (2)  consider setting -excludeTmpFiles in case of IOExceptions\n");
			}
		} catch(Exception e) {
			out.println(e);
			return null;
		}
		try {
			out.println(Grep.getResults(settings));
		} catch(Exception e) {
			out.println("No job output found in " + settings.get("tempDir").toString());
			out.println(e);
		}
		return null;
}});
} catch(Exception e) { System.out.println(e); }
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
	}

}
