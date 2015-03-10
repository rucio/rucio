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

import java.io.*;
import java.util.*;
import java.text.*;

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


import org.apache.commons.lang.ArrayUtils;

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
public class HttpMonitoring extends HttpServlet {
	private static final long serialVersionUID = 1L;
	public static DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH);
       
	/**
	* @see HttpServlet#HttpServlet()
	*/
	public HttpMonitoring() {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		final PrintWriter out = response.getWriter();
		final String report_tyoe = request.getParameter("report");
		final String fileName = "http_monitoring_"+request.getParameter("report")+".csv";
		String date = request.getParameter("date");
		String filter = null;
		int requestTopN = -1;
		int counter = 0;
    ArrayList<Integer> othersColIndex = new ArrayList<Integer>();
    boolean filledOthers = false;

    if (!request.getParameterMap().containsKey("raw")) {
      response.setContentType("text/csv");
    } else {
      response.setContentType("text/plain");
		}
		if (!request.getParameterMap().containsKey("date")) {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
			date = new SimpleDateFormat("yyyy-MM-dd").format(new Date());
		}

		if (request.getParameterMap().containsKey("account")) {
			filter = ".*?\t"+request.getParameter("account")+"\t.*$";
		}

		try {
			requestTopN = Integer.parseInt(request.getParameter("top"));
		} catch(NumberFormatException e) {;} catch(Exception e) {System.out.println(e);}

		FileSystem fs = FileSystem.get(new Configuration());
		BufferedReader br=new BufferedReader(new InputStreamReader(fs.open(new Path("/user/rucio01/reports/" + date + "/" + fileName))));

		String line=br.readLine();
    // First line is the header.
    String[] cols = line.split("\\t");
    for(int i=0; i < cols.length; i++)  //  Every col not starting with group is considered a number
      if(!cols[i].matches("^group\\.*$"))
        othersColIndex.add(new Integer(i));

    double[] others = new double[cols.length];
    for(int i = 0; i < others.length; i++) {
      others[i] = 0.0;
    }

		while (line != null){
      if ((filter == null) || (line.matches(filter))) {
        counter++;
        if ((requestTopN == -1) || (counter < requestTopN)) {
					out.write(line+"\n");
        } else { // Aggregate numbers
          if(!filledOthers) {
            filledOthers = true;
          }
          cols = line.split("\\t");
          for(Integer index: othersColIndex) {
            try {
              others[index] += Double.parseDouble(cols[index]); 
            } catch(NumberFormatException e) {;} catch(Exception e) {System.out.println(e);}
          }
				}
      }
			// Read next line
			line=br.readLine();
		}
    if(filledOthers) {
      line = date;
      for(int i = 1; i <  others.length; i++) {
        line += new String("\t" + ((others[i] == 0) ? "Others (Pos: "+requestTopN+" - "+counter+")" : String.format("%d", (long)others[i])));
      }
      out.write(line+"\n");
    }
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
	}

}
