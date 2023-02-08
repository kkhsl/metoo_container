package com.metoo.nspm.core.utils;

import com.metoo.nspm.vo.Result;

import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 * Title: ResponseUtil.java
 * </p>
 *
 * <p>
 * Description: 异常捕获结果处理工具类
 * </p>
 *
 * <author>
 * HKK
 * </author>
 */
public class ResponseUtil {

    public static Object unlogin() {
        return result(401, "Log in");
    }

    public static Object unauthz() {
        return result(403, "Insufficient authority");
    }

    public static Object expired() {
        return result(4011, "Login expired");
    }

    public static Object badArgumentValue() {
        return result(402, "参数错误");
    }

    public static Object nullPointException() {
        return result(502, "Data does not exist");
    }

    public static Object arithmeticException() {
        return result(402, "Data exception");
    }

    public static Object serious() {
        return result(502, "系统异常");
    }

    public static Object httpRequestMethodNotSupportedException() {
        return new Result(405, "Method Not Allowed");
    }

    public static Object fileNotFoundException() {
        return new Result(1, "fileNotFound");
    }

    public static Object add() {
        return new Result(200, "Successfully added");
    }

    public static Object badArgument() { return fail(400, "Parameter is error");}

    public static Object badArgument(String message) { return fail(400, message);} //未找到指定资源

    public static Object badArgumentRepeatedName() { return fail(400, "名称重复");} //未找到指定资源

    public static Object resourceNotFound() { return fail(400, "not found");} //未找到指定资源

    public static Object client() { return fail(400, "客户端错误");} // 禁止随意更改参数

    public static Object badArgument(int code, String message) { return fail(code, message);} //未找到指定资源

    public static Object update() {
        return new Result(200, "Modify successfully");
    }

    public static Object delete() {
        return new Result(200, "Successfully delete");
    }

    public static Object query(Map data) {
        return new Result(200, "Successfully query", data);
    }
    public static Object query() {
        return new Result(200, "Successfully query");
    }

    public static Object prohibitDel() {
        return new Result(501, "Cannot delete, delete the associated item first");
    }

    public static Object error() { return new Result(500, "Submit failure");  }

    public static Object error(String message) { return new Result(500, message);  }

    public static Object error(int code, String message) { return new Result(500, message);  }

    public static Object fail(String data) {
        return new Result(500, data);
    }

    public static Object ok(){return new Result(200, "Successfully");}

    public static Object ok(Object data){return new Result(200, "Successfully", data);}

    public static Object notFound(){return new Result(404, "请求的资源不存在");}

    public static Object missingparameter(){return new Result(400, "缺少必填参数");}

    public static Object InvalidFormatException(){return new Result(400, "数据格式异常");}

    public static Object ok(boolean flag){
        if(flag){
            return new Result(200, "保存成功");
        }
        return new Result(500, "保存失败");
    }

    public static Object noContent(){return new Result(204, "Successfully");}

    public static Object fail(int errno, String errmsg) {
        Map<String, Object> obj = new HashMap<String, Object>();
        obj.put("code", errno);
        obj.put("msg", errmsg);
        return obj;
    }

    public static Object result(int errno, String errmsg) {
        Result obj = new Result(errno, errmsg);
        return obj;
    }
}
