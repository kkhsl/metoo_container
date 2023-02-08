package com.metoo.nspm.core.video;


import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class ChangeVideo {

    public static void main(String[] args) {
        ChangeVideo.convert("C:\\Users\\46075\\Desktop\\20210323040120436\\merge.ts",
                "C:\\Users\\46075\\Desktop\\20210323040120436\\temp.mp4");
    }

    /**
     * @param inputFile:需要转换的视频
     * @param outputFile：转换后的视频w
     * @return
     */
    public static boolean convert(String inputFile, String outputFile) {
        if (!checkfile(inputFile)) {
            return false;
        }
        return process(inputFile, outputFile);
    }

    // 检查文件是否存在
    private static boolean checkfile(String path) {
        File file = new File(path);
        if (!file.isFile()) {
            return false;
        }
        return true;
    }

    /**
     * @param inputFile
     * @param outputFile
     * @return 转换视频文件
     */
    private static boolean process(String inputFile, String outputFile) {
        int type = checkContentType(inputFile);
        boolean status = false;
        if (type == 0) {
            status = processFLV(inputFile, outputFile);// 直接将文件转为flv文件
        } else if (type == 2) {
            String avifilepath = processAVI(type, inputFile);
            if (avifilepath == null)
                return false;// avi文件没有得到
            status = processFLV(avifilepath, outputFile);// 将avi转为flv
        }
        return status;
    }

    private static int checkContentType(String inputFile) {
        String type = inputFile.substring(inputFile.lastIndexOf(".") + 1, inputFile.length()).toLowerCase();
        // ffmpeg能解析的格式：（asx，asf，mpg，wmv，3gp，mp4，mov，avi，flv等）
        if (type.equals("avi")) {
            return 0;
        } else if (type.equals("mpg")) {
            return 0;
        } else if (type.equals("wmv")) {
            return 0;
        } else if (type.equals("3gp")) {
            return 0;
        } else if (type.equals("mov")) {
            return 0;
        } else if (type.equals("mp4")) {
            return 0;
        } else if (type.equals("asf")) {
            return 0;
        } else if (type.equals("asx")) {
            return 0;
        } else if (type.equals("flv")) {
            return 0;
        }
        if (type.equals("ts")) {
            return 0;
        }
        // 对ffmpeg无法解析的文件格式(wmv9，rm，rmvb等),
        // 可以先用别的工具（mencoder）转换为avi(ffmpeg能解析的)格式.
        else if (type.equals("wmv9")) {
            return 1;
        } else if (type.equals("rm")) {
            return 1;
        } else if (type.equals("rmvb")) {
            return 1;
        }
        return 9;
    }

    // ffmpeg能解析的格式：（asx，asf，mpg，wmv，3gp，mp4，mov，avi，flv等）直接转换为目标视频
    private static boolean processFLV(String inputFile, String outputFile) {

        if (!checkfile(inputFile)) {
            System.out.println(inputFile + " is not file");
            return false;
        }
        List<String> commend = new ArrayList<String>();
        commend.add(Constants.ffmpegPath);
        //./ffmpeg -i /opt/spzh/yysp.avi -f mp4 -acodec libfaac
        // -vcodec libxvid -qscale 7 -dts_delta_threshold 1 -y /opt/spzh/out/yysp8.mp4
        // Linux
        commend.add("-i");// 设定输入流
        commend.add(inputFile);
        commend.add("-acodec");// 设定声音编解码器，未设定则使用与输入流相同的编解码器
        commend.add("copy");// 表示原始编解码数据必须被拷贝
        commend.add("-vcodec");// 强制使用codec编解码方式('copy' to copy stream)
        commend.add("copy");
        commend.add("-absf");
        commend.add("aac_adtstoasc");
        // commend.add("-f");
        commend.add(outputFile);
//windows
      /* commend.add("-i");
        commend.add(inputFile);
        commend.add("-ab");
        commend.add("128");
        commend.add("-acodec");
        commend.add("libfaac");
        commend.add("-ac");
        commend.add("1");
        commend.add("-ar");
        commend.add("22050");
        commend.add("-r");
        commend.add("24");
        commend.add("-y");
        commend.add(outputFile);*/
        //Windows
       /* commend.add("-i");
        commend.add(inputFile);
        commend.add("-ab");
        commend.add("128");
        commend.add("-acodec");
        commend.add("libmp3lame");
        commend.add("-ac");
        commend.add("1");
        commend.add("-ar");
        commend.add("22050");
        commend.add("-r");
        commend.add("29.97");
        // 高品质
        commend.add("-qscale");
        commend.add("6");
        // 低品质
        // commend.add("-b");
        // commend.add("512");
        commend.add("-y");

        commend.add(outputFile);*/
   /*     StringBuffer test = new StringBuffer();
        for (int i = 0; i < commend.size(); i++) {
            test.append(commend.get(i) + " ");
        }

        SystemTest.out.println(test);

        try {

            ProcessBuilder processBuilder = new ProcessBuilder();
            processBuilder.command(commend);
            processBuilder.start();
            return "processFLVtrue";
        } catch (Exception e) {
            e.printStackTrace();
            return e.getMessage();
        }*/
        StringBuffer instruct = new StringBuffer();
        for (int i = 0; i < commend.size(); i++)
            instruct.append(commend.get(i) + " ");
        try {
            Runtime rt = Runtime.getRuntime();
            Process proc = rt.exec(instruct.toString());
            InputStream stderr = proc.getErrorStream();
            InputStreamReader isr = new InputStreamReader(stderr);
            BufferedReader br = new BufferedReader(isr);
            String line = null;
            while ((line = br.readLine()) != null) ;
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    // 对ffmpeg无法解析的文件格式(wmv9，rm，rmvb等),
    // 可以先用别的工具（mencoder）转换为avi(ffmpeg能解析的)格式.
    private static String processAVI(int type, String inputFile) {
        File file = new File(Constants.mp4path);
        if (file.exists())
            file.delete();
        List<String> commend = new ArrayList<String>();
        commend.add(Constants.mencoderPath);
        commend.add(inputFile);
        commend.add("-oac");
        commend.add("mp3lame");
        commend.add("-lameopts");
        commend.add("preset=64");
        commend.add("-ovc");
        commend.add("xvid");
        commend.add("-xvidencopts");
        commend.add("bitrate=600");
        commend.add("-of");
        commend.add("avi");
        commend.add("-o");
        commend.add(Constants.mp4path);
        StringBuffer test = new StringBuffer();
        for (int i = 0; i < commend.size(); i++) {
            test.append(commend.get(i) + " ");
        }

        System.out.println(test);
        try {
            ProcessBuilder builder = new ProcessBuilder();
            builder.command(commend);
            Process p = builder.start();

            final InputStream is1 = p.getInputStream();
            final InputStream is2 = p.getErrorStream();
            new Thread() {
                public void run() {
                    BufferedReader br = new BufferedReader(new InputStreamReader(is1));
                    try {
                        String lineB = null;
                        while ((lineB = br.readLine()) != null) {
                            if (lineB != null)
                                System.out.println(lineB);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }.start();
            new Thread() {
                public void run() {
                    BufferedReader br2 = new BufferedReader(new InputStreamReader(is2));
                    try {
                        String lineC = null;
                        while ((lineC = br2.readLine()) != null) {
                            if (lineC != null)
                                System.out.println(lineC);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }.start();

            // 等Mencoder进程转换结束，再调用ffmepg进程
            p.waitFor();
            System.out.println("who cares");
            return Constants.avifilepath;
        } catch (Exception e) {
            System.err.println(e);
            return null;
        }
    }

}
