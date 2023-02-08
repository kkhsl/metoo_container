package com.metoo.nspm.core.utils.poi;

import com.metoo.nspm.entity.nspm.NetworkElement;
import org.apache.poi.hssf.usermodel.HSSFSheet;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.streaming.SXSSFWorkbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Java操作Excel的两种方式
 *
 * 第一种方式：POI（Apache）
 *  优点：方便生成数据报表、数据批量上传、数据备份等...
 *  缺点：如果将文件一次性全部加载到内存可能导致OOM(Out OfMemory)(内存占用增加)
 *
 * 第二种方式：EasyExcel(Alibaba)，是对POI的封装；减少内存占用，避免OOM
 *  优点：easyExcel解析Excel时没有将文件数据一次性全部加载到内存中，二十从磁盘上一行行读取数据，逐个解析
 */
public class PoiUtil {

    public static void main(String[] args) {
        List<NetworkElement> networkElements = new ArrayList<NetworkElement>();
        NetworkElement networkElement = new NetworkElement();
        networkElement.setDeviceName("test");
        networkElement.setIp("1.1.1.1");
        networkElement.setVendorName("vendor");
        networkElement.setDeviceTypeName("deviceType");
        networkElement.setDescription("desc");
        networkElements.add(networkElement);
        exportHFFS(networkElements);
    }

    /**
     * 03版Excel：导入导出
     */
    public static void exportHFFS(List<NetworkElement> ne){
        //时间
        long begin = System.currentTimeMillis();
        // 创建一个工作薄
        Workbook workbook = new HSSFWorkbook();
        // 创建一个工作表
        Sheet sheet = workbook.createSheet("设备信息");
        // 创建行 默认从0开始
        Row row1 = sheet.createRow(0);
        // 创建单元格 默认从0开始
        // （1,1）
        Cell cell1 = row1.createCell(0);
        cell1.setCellValue("序号");
        Cell cell2 = row1.createCell(1);
        cell2.setCellValue("设备名称");
        Cell cell3 = row1.createCell(2);
        cell3.setCellValue("管理地址");
        Cell cell4 = row1.createCell(3);
        cell4.setCellValue("厂商");
        Cell cell5 = row1.createCell(4);
        cell5.setCellValue("类型");
        Cell cell6 = row1.createCell(5);
        cell6.setCellValue("用途描述");
        Cell cell7 = row1.createCell(6);
        cell7.setCellValue("SNMP版本");
        Cell cell8 = row1.createCell(7);
        cell8.setCellValue("SNMP community");
        // 写入数据
        for (int rowNum = 1; rowNum <= ne.size(); rowNum++) {
            Row row = sheet.createRow(rowNum);
            NetworkElement networkElement = ne.get(rowNum - 1);
            Cell cell21 = row.createCell(0);
            cell21.setCellValue(rowNum);
            Cell cell22 = row.createCell(1);
            cell22.setCellValue(networkElement.getDeviceName());
            Cell cell23 = row.createCell(2);
            cell23.setCellValue(networkElement.getIp());
            Cell cell24 = row.createCell(3);
            cell24.setCellValue(networkElement.getVendorName());
            Cell cell25 = row.createCell(4);
            cell25.setCellValue(networkElement.getDeviceTypeName());
            Cell cell26 = row.createCell(5);
            cell26.setCellValue(networkElement.getDescription());
            Cell cell27 = row.createCell(6);
            cell27.setCellValue("V2");
            Cell cell28 = row.createCell(7);
            cell28.setCellValue("read");
        }

        //生成一张表(IO流)，03版本就是使用xls结尾
        FileOutputStream fos = null;
        try {

            fos = new FileOutputStream("C:\\Users\\46075\\Desktop\\metoo\\ExcelIO\\test\\" + "设备信息.xls");
            //输出
            try {
//                response.setContentType("application/octet-stream");
//                response.setHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode(file.getName(), "UTF-8"));
                workbook.write(fos);
            } catch (IOException e) {
                e.printStackTrace();
            }finally {
                //关闭流
                try {
                    fos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                long end = System.currentTimeMillis();
                System.out.println("耗时："+(end-begin));
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static void exportXSSF(){
        //时间
        long begin = System.currentTimeMillis();
        // 创建一个工作簿
        Workbook workbook = new XSSFWorkbook();
    }

    public static void importXSSF(){
        //时间
        long begin = System.currentTimeMillis();
        // 创建一个工作簿
        Workbook workbook = new SXSSFWorkbook();
    }


}
