package com.metoo.nspm.core.utils.poi;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.google.gson.Gson;
import com.metoo.nspm.core.utils.StringUtils;
import com.metoo.nspm.entity.nspm.NetworkElement;
import lombok.val;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.apache.poi.ss.usermodel.*;

import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.beans.BeanUtils;
import org.springframework.web.multipart.MultipartFile;
import sun.nio.ch.Net;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.text.NumberFormat;
import java.util.*;

/**
 * Excel 导入导出
 * https://blog.csdn.net/wuxiaopengnihao1/article/details/126686520
 */
public class ExcelUtil {

    private static final String XLSX = ".xlsx";
    private static final String XLS = ".xls";
    private static final String ROW_NUM = "rowNum";
    private static final String ROW_DATA = "rowData";
    private static final String ROW_TIPS = "rowTips";
    private static final NumberFormat NUMBER_FORMAT = NumberFormat.getNumberInstance();

    public static <T> List<NetworkElement> readMultipartFile(MultipartFile  file, Class<T> clazz) throws Exception {
        JSONArray array = readMultipartFile(file);
        List<NetworkElement> list = new ArrayList<>();
        for (int i = 0; i < array.size(); i++) {
            NetworkElement networkElement = JSON.toJavaObject(array.getJSONObject(i), NetworkElement.class);
            list.add(networkElement);
        }
        return list;
    }

    public static JSONArray readMultipartFile(MultipartFile mFile) throws Exception {
        return readExcel(mFile);
    }

    private static <T> List<T> getBeanList(JSONArray array, Class<T> clazz) throws Exception {
        List<T> list = new ArrayList<>();
        Map<Integer, String> uniqueMap = new HashMap<>(8);
        for (int i = 0; i < array.size(); i++) {
            list.add(getBean(clazz, array.getJSONObject(i), uniqueMap));
        }
        return list;
    }

    /**
     * 获取每个对象的数据
     */
    private static <T> T getBean(Class<T> c, JSONObject obj, Map<Integer, String> uniqueMap) throws Exception {
        T t = c.newInstance();
        Field[] fields = c.getDeclaredFields();
        List<String> errMsgList = new ArrayList<>();
        boolean hasRowTipsField = false;
        StringBuilder uniqueBuilder = new StringBuilder();
        int rowNum = 0;
        for (Field field : fields) {
            // 行号
            if (field.getName().equals(ROW_NUM)) {
                rowNum = obj.getInteger(ROW_NUM);
                field.setAccessible(true);
                field.set(t, rowNum);
                continue;
            }
            // 是否需要设置异常信息
            if (field.getName().equals(ROW_TIPS)) {
                hasRowTipsField = true;
                continue;
            }
            // 原始数据
            if (field.getName().equals(ROW_DATA)) {
                field.setAccessible(true);
                field.set(t, obj.toString());
                continue;
            }
            // 设置对应属性值
            setFieldValue(t,field, obj, uniqueBuilder, errMsgList);
        }
        // 数据唯一性校验
        if (uniqueBuilder.length() > 0) {
            if (uniqueMap.containsValue(uniqueBuilder.toString())) {
                Set<Integer> rowNumKeys = uniqueMap.keySet();
                for (Integer num : rowNumKeys) {
                    if (uniqueMap.get(num).equals(uniqueBuilder.toString())) {
                        errMsgList.add(String.format("数据唯一性校验失败,(%s)与第%s行重复)", uniqueBuilder, num));
                    }
                }
            } else {
                uniqueMap.put(rowNum, uniqueBuilder.toString());
            }
        }
        // 失败处理
        if (errMsgList.isEmpty() && !hasRowTipsField) {
            return t;
        }
        StringBuilder sb = new StringBuilder();
        int size = errMsgList.size();
        for (int i = 0; i < size; i++) {
            if (i == size - 1) {
                sb.append(errMsgList.get(i));
            } else {
                sb.append(errMsgList.get(i)).append(";");
            }
        }
        // 设置错误信息
        for (Field field : fields) {
            if (field.getName().equals(ROW_TIPS)) {
                field.setAccessible(true);
                field.set(t, sb.toString());
            }
        }
        return t;
    }

    private static <T> void setFieldValue(T t, Field field, JSONObject obj, StringBuilder uniqueBuilder, List<String> errMsgList) {
//        // 获取 ExcelImport 注解属性
       NetworkElement networkElement = JSON.toJavaObject(obj, NetworkElement.class);
        System.out.println(networkElement);
//        // 其余情况根据类型赋值
//        String fieldClassName = field.getType().getSimpleName();
//        try {
//            if ("String".equalsIgnoreCase(fieldClassName)) {
//                field.set(t, val);
//            } else if ("boolean".equalsIgnoreCase(fieldClassName)) {
//                field.set(t, Boolean.valueOf(val));
//            } else if ("int".equalsIgnoreCase(fieldClassName) || "Integer".equals(fieldClassName)) {
//                try {
//                    field.set(t, Integer.valueOf(val));
//                } catch (NumberFormatException e) {
//                    errMsgList.add(String.format("[%s]的值格式不正确(当前值为%s)", cname, val));
//                }
//            } else if ("double".equalsIgnoreCase(fieldClassName)) {
//                field.set(t, Double.valueOf(val));
//            } else if ("long".equalsIgnoreCase(fieldClassName)) {
//                field.set(t, Long.valueOf(val));
//            } else if ("BigDecimal".equalsIgnoreCase(fieldClassName)) {
//                field.set(t, new BigDecimal(val));
//            }
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
    }

    private static LinkedHashMap<String, String> getKvMap(String kv) {
        LinkedHashMap<String, String> kvMap = new LinkedHashMap<>();
        if (kv.isEmpty()) {
            return kvMap;
        }
        String[] kvs = kv.split(";");
        if (kvs.length == 0) {
            return kvMap;
        }
        for (String each : kvs) {
            String[] eachKv = StringUtils.getStr(each).split("-");
            if (eachKv.length != 2) {
                continue;
            }
            String k = eachKv[0];
            String v = eachKv[1];
            if (k.isEmpty() || v.isEmpty()) {
                continue;
            }
            kvMap.put(k, v);
        }
        return kvMap;
    }

    public static JSONArray readExcel(MultipartFile mFile){
        if(mFile != null){
            // 解析表格数据
            InputStream in;
            String fileName;
            try {
                in = mFile.getInputStream();
                fileName = StringUtils.getStr(mFile.getOriginalFilename()).toLowerCase();
                Workbook book;
                if (fileName.endsWith(XLSX)) {
                    book = new XSSFWorkbook(in);
                } else if (fileName.endsWith(XLS)) {
                    POIFSFileSystem poifsFileSystem = new POIFSFileSystem(in);
                    book = new HSSFWorkbook(poifsFileSystem);
                } else {
                    return new JSONArray();
                }
                JSONArray array = read(book);
                in.close();
                return array;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return new JSONArray();
    }

    private static JSONArray read(Workbook book) {
        // 获取 Excel 文件第一个 Sheet 页面
        Sheet sheet = book.getSheetAt(0);
        return readSheet(sheet);
    }

    private static JSONArray readSheet(Sheet sheet) {
        // 首行下标
        int rowStart = sheet.getFirstRowNum();
        // 尾行下标
        int rowEnd = sheet.getLastRowNum();
        // 获取表头行
        Row headRow = sheet.getRow(rowStart);
        if (headRow == null || rowStart == rowEnd) {// 只有表头
            return new JSONArray();
        }

        int cellStart = headRow.getFirstCellNum();
        int cellEnd = headRow.getLastCellNum();
        Map<Integer, String> keyMap = new HashMap<>();
        for (int j = cellStart; j < cellEnd; j++) {
            // 获取表头数据
            String val = getCellValue(headRow.getCell(j));
            if (val != null && val.trim().length() != 0) {
                keyMap.put(j, val);
            }
        }
        // 如果表头没有数据则不进行解析
        if (keyMap.isEmpty()) {
            return (JSONArray) Collections.emptyList();
        }
        // 获取每行JSON对象的值
        JSONArray array = new JSONArray();
        // 如果首行与尾行相同，表明只有一行，返回表头数据
//        if (rowStart == rowEnd) {
//            JSONObject obj = new JSONObject();
//            // 添加行号
//            obj.put(ROW_NUM, 1);
//            for (int i : keyMap.keySet()) {
//                obj.put(keyMap.get(i), "");
//            }
//            array.add(obj);
//            return array;
//        }
        for (int i = rowStart + 1; i <= rowEnd; i++) {
            Row eachRow = sheet.getRow(i);
            JSONObject obj = new JSONObject();
            // 添加行号
            obj.put(ROW_NUM, i + 1);
            StringBuilder sb = new StringBuilder();
            for (int k = cellStart; k < cellEnd; k++) {
                if (eachRow != null) {
                    String val = getCellValue(eachRow.getCell(k));
                    // 所有数据添加到里面，用于判断该行是否为空
                    sb.append(val);
                    obj.put(keyMap.get(k), val);
                }
            }
            if (sb.length() > 0) {
                array.add(obj);
            }
        }
        return array;
    }

    private static String getCellValue(Cell cell) {
        // 空白或空
        if (cell == null || cell.getCellTypeEnum() == CellType.BLANK) {
            return "";
        }
        // String类型
        if (cell.getCellTypeEnum() == CellType.STRING) {
            String val = cell.getStringCellValue();
            if (val == null || val.trim().length() == 0) {
                return "";
            }
            return val.trim();
        }
        // 数字类型
        if (cell.getCellTypeEnum() == CellType.NUMERIC) {
            // 科学计数法类型
            return NUMBER_FORMAT.format(cell.getNumericCellValue()) + "";
        }
        // 布尔值类型
        if (cell.getCellTypeEnum() == CellType.BOOLEAN) {
            return cell.getBooleanCellValue() + "";
        }
        // 错误类型
        return cell.getCellFormula();
    }



}
