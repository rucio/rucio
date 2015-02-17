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

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.text.ParseException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.io.IntWritable;
import org.apache.hadoop.io.Text;

import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.Mapper;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.Mapper;
import org.apache.hadoop.mapreduce.Reducer;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;

import org.apache.log4j.Level;


import org.apache.commons.lang.StringUtils;

import org.apache.hadoop.mapreduce.lib.input.FileSplit;
import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.Mapper;

public class Grep {
  public static DateFormat date_format = new SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH);

  public static final Map<String, ArrayList<String>> TYPES; static {
    TYPES = new HashMap<String, ArrayList<String>>();
    TYPES.put("automatix", new ArrayList<String>(Arrays.asList("automatix")));
    TYPES.put("conveyor", new ArrayList<String>(Arrays.asList("conveyor")));
    TYPES.put("hermes", new ArrayList<String>(Arrays.asList("hermes")));
    TYPES.put("judge", new ArrayList<String>(Arrays.asList("judge")));
    TYPES.put("kronos", new ArrayList<String>(Arrays.asList("kronos")));
    TYPES.put("necromancer", new ArrayList<String>(Arrays.asList("necromancer")));
    TYPES.put("reaper", new ArrayList<String>(Arrays.asList("reaper")));
    TYPES.put("server", new ArrayList<String>(Arrays.asList("server")));
    TYPES.put("transmogrifier", new ArrayList<String>(Arrays.asList("transmogrifier")));
    TYPES.put("undertaker", new ArrayList<String>(Arrays.asList("undertaker")));
  }

  public static String printJobSummary(Map<String, Object> settings) {
    String jobSummary = "Job Settings Summary:\n";
    jobSummary += "\tRegular Expression: " + (String)settings.get("regex") + "\n";
    jobSummary += "\tService Types: "+ (ArrayList<String>)settings.get("types") + "\n";
    jobSummary += "\tFrom Date: " + date_format.format((Date)settings.get("fromDate"))+"\n";
    jobSummary += "\tTo Date: " +  date_format.format((Date)settings.get("toDate"))+"\n";
    jobSummary += "\tTemp Directory: " + settings.get("tempDir").toString()+"\n";
    if(settings.get("excludeTmpFiles") != null) {
      jobSummary += "\tExcluded TMP files:\n";
      for(String file : (ArrayList<String>)settings.get("excludeTmpFiles"))
        jobSummary += "\t\t"+file+"\n";
    }
    return jobSummary;
  }

  private static void assignInputFiles(FileSystem fs, Map<String, Object> settings, Job job) throws ParseException, IOException, Grep.NoInputFilesFound {
    // Extend date range and type to iderive explicite set of input files 
    List<Date> dates = new ArrayList<Date>();
    Calendar cal = Calendar.getInstance();
    Boolean excludeTmpFiles = (settings.get("excludeTmpFiles") != null);


    cal.setTime((Date)settings.get("fromDate"));
    while (!cal.getTime().after((Date)settings.get("toDate"))) {
      dates.add(cal.getTime());
      cal.add(Calendar.DATE, 1);
    }

    for(int i=0; i < dates.size(); i++) {
      for(String type: (ArrayList<String>)settings.get("types")) {
        Path p = new Path("/user/rucio01/logs/"+type+"/*"+date_format.format(dates.get(i))+"*");
        for (FileStatus file : fs.globStatus(p)) {
	  if((excludeTmpFiles) && (file.getPath().toString().endsWith("tmp"))) {
            ((List<String>)settings.get("excludeTmpFiles")).add(file.getPath().getName().toString()); 
            continue;
          }
          FileInputFormat.addInputPath(job, file.getPath());
        }
      }
    }
    if (FileInputFormat.getInputPaths(job).length == 0) {
      throw new Grep.NoInputFilesFound("For type " + settings.get("types") 
                             + " from " + date_format.format(dates.get(0)) 
                             + " to " +  date_format.format(dates.get(dates.size()-1))
                             + " no log files coiuld be found on HDFS.");
    }
  }

  public static boolean runJob(Map<String, Object> settings) throws Exception {
    // Job configuration
    Configuration conf = new Configuration();
    conf.set("regex", (String)settings.get("regex"));  // Passing regex to distributed mapper class instances
    conf.set("mapreduce.map.log.level", "ERROR"); // Seems to have no impact, thus TODO: get rid of F*@&#G console output

    // Actual Hadoop job creation
    Job job = Job.getInstance(conf, ((Path)settings.get("tempDir")).toString());
    job.setJarByClass(Grep.class);
    job.setMapperClass(MapClass.class);

    // Derive and assign input files match the criteria provided in settings
    FileSystem fs = DistributedFileSystem.get(conf);
    Grep.assignInputFiles(fs, settings, job);

    // Define output
    FileOutputFormat.setOutputPath(job, (Path)settings.get("tempDir"));
    job.setOutputKeyClass(Text.class);
    job.setOutputKeyClass(Text.class);
    job.setOutputValueClass(Text.class);

    // Print job summary before starting/defining actual Hadop job
    return job.waitForCompletion(false);

  }

  public static void main(String[] args) throws Exception {
    // Parse provided command line arguments
    Map<String, Object> settings = Grep.parseCommandLineArguments(args); 
    if ((Boolean)settings.get("printUsage")) {
      System.out.println((String)settings.get("errorMessage"));
      System.out.println(Grep.printUsage());
      System.exit(-1);
    }

    // Derive tmp dir for job output
    settings.put("tempDir", new Path("rucio-grep-"+Integer.toString(new Random().nextInt(Integer.MAX_VALUE))));
    System.out.println(Grep.printJobSummary(settings));

    // Execute MR job
    try {
      if (!Grep.runJob(settings)) {
        System.out.println("Something went wrong :-(");
        System.out.println("Hints: (1) do not redirect stderr to /dev/null (2)  consider setting -excludeTmpFiles in case of IOExceptions");
      }
    } catch(Grep.NoInputFilesFound e) {
      System.out.println(e);
      System.exit(1);
    }
    try {
    System.out.println(Grep.getResults(settings));
    } catch(Exception e) {
      System.out.println("No job output found in " + settings.get("tempDir").toString());
      System.out.println(e);
    }
    System.exit(0);
  }

  public static String getResults(Map<String, Object> settings) throws Exception {
    Configuration conf = new Configuration();
    FileSystem fs = DistributedFileSystem.get(conf);
    String results = new String();

    // Returning results from tempDir
    BufferedReader br = new BufferedReader(new InputStreamReader(fs.open(new Path(((Path)settings.get("tempDir")).toString()+"/part-r-00000"))));
    String line;
    for (line=br.readLine(); line != null; line=br.readLine()) { results += line+"\n"; }

    // Clean-up tempDir on HDFS
    fs.delete((Path)settings.get("tempDir"), true);

    return results;
  }

  public static Map<String, Object> parseCommandLineArguments(String[] args) {
    Map<String, Object> results = new HashMap<String, Object>();
    results.put("printUsage", new Boolean(false));
    results.put("types", new ArrayList<String>());
    results.put("fromDateProvided", new Boolean(false));
    results.put("toDateProvided", new Boolean(false));

    for(int i=0;i<args.length && !((Boolean)results.get("printUsage")); i++) {
      args[i] = args[i].trim();
      switch(args[i]) {
        case "-type":
          String t = args[++i];
          if (t.equals("ALL")) {
            for (String at : TYPES.keySet()) {
              for (String type : TYPES.get(at)) { ((ArrayList<String>)results.get("types")).add(type); }
            }
          } else if (TYPES.containsKey(t)) {
            for (String type : TYPES.get(t)) { ((ArrayList<String>)results.get("types")).add(type); }
          } else {
            results.put("errorMessage", "Error: Unknown type argument provided => " + t);
            results.put("printUsage", new Boolean(true));
          }
          break;
        case "-search":
          args[i+1] = "(.*)"+args[i+1]+"(.*)"; // Decorating the search string to represent a substrign search in regex
        case "-regex":
          if (results.get("regex") == null) { results.put("regex", args[++i]); }
          else {
            results.put("errorMessage", "Error: Multiple regex/search arguments provided.");
            results.put("printUsage", new Boolean(true));
          }
          break;
        case "-date":
        case "-fromDate":
          if (results.get("fromDate") == null) {
            try {
              results.put("fromDate", Grep.date_format.parse(args[++i]));
              results.put("fromDateProvided", new Boolean(true));
            } catch (java.text.ParseException e) {
              results.put("fromDate", null);
              results.put("errorMessage", "Error: unable to parse <fromDate>.");
              results.put("printUsage", new Boolean(true));
            }
          } else {
            results.put("errorMessage", "Error: Multiple fromDate arguments provided.");
            results.put("printUsage", new Boolean(true));
          }
          if (args[i-1].equals("-date")) { i--; } // If -date was pprovided, skip the break and reuse the input argument for toDate as well
          else { break; }
        case "-toDate":
          if (results.get("toDate") == null) {
            try {
              results.put("toDate", Grep.date_format.parse(args[++i]));
              results.put("toDateProvided", new Boolean(true));
            } catch (java.text.ParseException e) {
              results.put("toDate", null);
              results.put("errorMessage", "Error: unable to parse <toDate>.");
              results.put("printUsage", new Boolean(true));
            }
            results.put("toDateProvided", new Boolean(true));
          } else {
            results.put("errorMessage", "Error: Multiple toDate arguments provided.");
            results.put("printUsage", new Boolean(true));
          }
          break;
        case "-excludeTmpFiles":
          results.put("excludeTmpFiles", new ArrayList<String>());
          break;
        default:
          results.put("errorMessage", "Error: Unknown argument provided: " + args[i]);
          results.put("printUsage", new Boolean(true));
      }
    }

    if (((ArrayList)results.get("types")).size() == 0) { results.put("errorMessage", "Error: At least one <type> argument is mandadtory."); results.put("printUsage", new Boolean(true)); }
    if (results.get("regex") == null) { results.put("errorMessage", "Error: <regex> argument is mandadtory."); results.put("printUsage", new Boolean(true));}
    if ((Boolean)results.get("toDateProvided") && !(Boolean)results.get("fromDateProvided")) { if(results.get("errorMessage") == null) results.put("errorMessage", "Error: When providing <toDate>, the argument <fromDate> becomes mandatory."); results.put("printUsage", new Boolean(true)); return results;}

    Calendar cal = Calendar.getInstance();
    if (!(Boolean)results.get("fromDateProvided")) { // Default: 3 days in the past
      cal.add(Calendar.DATE, -3);
      try { results.put("fromDate", Grep.date_format.parse(date_format.format(cal.getTime()))); } catch (Exception e) { results.put("errorMessage", e); }
    }
    if (!(Boolean)results.get("toDateProvided")) { // Default: Today
      try { results.put("toDate", Grep.date_format.parse(date_format.format(new Date()))); } catch (Exception e) { results.put("errorMessage", e); }
    }

    cal.setTime((Date)results.get("fromDate"));
    if (cal.getTime().after((Date)results.get("toDate"))) {
      results.put("errorMessage", "Error: <toDate> must be after <fromDate>");
      results.put("printUsage", new Boolean(true));
    }
    return results;
  }

  public static String printUsage() {
    String usageString = "Usage: Grep -type <type> -regex <regex> -search <substring>-fromDate <fromDate> -toDate <toDate> -excludeTmpFiles\n"
                       + "<type>: The following values are supported. Can be provided multiple times.\n"
                       + "  ALL automatix conveyor  hermes  judge kronos\n"
                       + "  necromancer reaper  server  transmogrifier  undertaker\n"
                       + "<regex>: supports Java regular expressions (alternating with search)\n"
                       + "<search>: performs a substring search, no addtioional functionality supported (alternating with regex)\n"
                       + "<fromDate>: Date when search periode starts in the format yyyy-mm-dd (optional, default: 3 days ago)\n"
                       + "<toDate>: Date when search periode ends in the format yyyy-mm-dd (optioinal, default: today)\n"
                       + "<date>: Seacrh only data for a specific date in the format yyyy-mm-dd (optioinal, alternating with fromDate and toDate)\n"
                       + "<excludeTmpFiles>: exclused input files with tmp as suffix. Should be set if MR job fails due to IOExceptions.\n";
    return usageString;
  }

  public static class NoInputFilesFound extends Exception {
    public NoInputFilesFound(String message) {
      super(message);
    }
  }

  public static class MapClass extends Mapper<Object, Text, Text, Text> {
    private String serviceName;
    private String nodeName;
  
/*
    public void setup(Context context) throws java.io.IOException, InterruptedException {
      InputSplit inputSplit = context.getInputSplit();
      serviceName = ((FileSplit) inputSplit).getPath().getName().split("\\.")[1];
      nodeName = ((FileSplit) inputSplit).getPath().getName().split("\\.")[2];
    }
 
*/ 
    public void map(Object key, Text value, Context context) throws IOException, InterruptedException {
      String line = value.toString();
      String[] split = line.split("\\s+");
      try {
      String date = split[0];
      if (split.length < 2) { return; }
      String tmp = "";
      for(int i = 2; i < split.length; i++) { tmp = (i < 4) ? tmp+split[i]+"\t" : tmp+split[i]+" ";} 
      String regex = context.getConfiguration().get("regex");
        if (line.matches(regex)) {
          context.write(new Text("date\t"), new Text(tmp));
        }
      } catch(java.lang.ArrayIndexOutOfBoundsException e) {
        context.write(new Text("[--------unknown-------- "+serviceName+"@"+nodeName+"]\t"), new Text(line));
      }
    }
  }
}
