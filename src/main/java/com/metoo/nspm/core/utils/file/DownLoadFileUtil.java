package com.metoo.nspm.core.utils.file;

import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URLEncoder;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

@Component
public class DownLoadFileUtil {

    public static void main(String[] args) {

        SimpleDateFormat sdf1 = new SimpleDateFormat("yyyyMMdd");
        String beginDate = sdf1.format(new Date());

        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
        Date date = null;

        try {
            date = sdf.parse(beginDate);
            Calendar cd = Calendar.getInstance();
            cd.setTime(date);
            cd.add(5, -1);
            System.out.println(sdf.format(cd.getTime()));
        } catch (ParseException e) {
            e.printStackTrace();
        }
    }

    private static final Logger logger = LoggerFactory.getLogger(DownLoadFileUtil.class);

    public static boolean downloadZip(File file, HttpServletResponse response) {
        try {
            InputStream fis = new BufferedInputStream(new FileInputStream(file.getPath()));
            byte[] buffer = new byte[fis.available()];
            fis.read(buffer);
            fis.close();
            response.reset();
            OutputStream toClient = new BufferedOutputStream(response.getOutputStream());
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode(file.getName(), "UTF-8"));
            toClient.write(buffer);
            toClient.flush();
            toClient.close();
            boolean var5 = true;
            return var5;
        } catch (IOException var9) {
            logger.error("downloadZip异常", var9);
            boolean var3 = false;
            return var3;
        } finally {
            ;
        }
    }

    public static boolean downloadZip(InputStream in, String fileName, HttpServletResponse response) {
        try {
            byte[] buffer = new byte[in.available()];
            in.read(buffer);
            in.close();
            response.reset();
            OutputStream toClient = new BufferedOutputStream(response.getOutputStream());
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode(fileName, "UTF-8"));
//            response.setHeader("Content-Disposition", "attachment;filename=" + new String(fileName.getBytes("UTF-8"), "ISO8859-1"));
            toClient.write(buffer);
            toClient.flush();
            toClient.close();
            boolean var5 = true;
            return var5;
        } catch (IOException var9) {
            logger.error("downloadZip异常", var9);
            boolean var3 = false;
            return var3;
        }
    }

    public static boolean downloadTemplate(String filePath, String fileName, HttpServletResponse response){
        OutputStream out = null;
        InputStream in = null;
        ByteArrayOutputStream bos = null;
//        String fileName = "资产设备导入模板";
        try {
            // 读取模板
            Resource res = new ClassPathResource(filePath + "/" + fileName);
            XSSFWorkbook workbook = new XSSFWorkbook(res.getInputStream());

            // 转换为字节流
            bos = new ByteArrayOutputStream();
            workbook.write(bos);
            byte[] barray = bos.toByteArray();
            in = new ByteArrayInputStream(barray);

            response.reset();
            response.setContentType("application/octet-stream");
            response.addHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode(fileName, "UTF-8"));
            out = response.getOutputStream();
            byte[] b = new byte[1024];
            int len;
            while ((len = in.read(b)) > 0) {
                out.write(b, 0, len);
            }
            out.flush();
            return true;
        } catch (Exception e) {

        } finally {
            if (null != in) {
                try {
                    in.close();
                } catch (IOException e) {
                }
                in = null;
            }
            if (null != out) {
                try {
                    out.close();
                } catch (IOException e) {
                }
                out = null;
            }
            if (null != bos) {
                try {
                    bos.flush();
                    bos.close();
                } catch (IOException e) {
                }
                out = null;
            }
        }
        return false;
    }
}
