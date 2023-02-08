package com.metoo.nspm.core.utils.bytes;

import org.springframework.stereotype.Component;

@Component
public class ByteConvertUtil {

    public static void main(String[] args) {

//        String size = "1098907610";
//        System.out.println(byteKb(size));
//        System.out.println(byteConverterMb(size));

//        System.out.println(Math.round(102.34375));
//        System.out.println(Math.round(102.34375) / 100.0);

    }

    public static String byteSize(String size){
        double length = Double.parseDouble(size);
        if(length < 1024){
            return length + "B";
        }else{
            length = length / 1024.0;
        }
        if (length < 1024) {
            return Math.round(length * 100) / 100.0 + "(KB)";
        } else {
            length = length / 1024.0;
        }
        if (length < 1024) {
            //因为如果以MB为单位的话，要保留最后1位小数，
            //因此，把此数乘以100之后再取余
            return Math.round(length * 100) / 100.0 + "(MB)";
        } else {
            //否则如果要以GB为单位的，先除于1024再作同样的处理
            return Math.round(length / 1024 * 100) / 100.0 + "(GB)";
        }
    }

    public static int byteConverterMb(String size){
        double length = Double.parseDouble(size);
        if (length > 0) {
            return (int) (Math.round(length / 1024 / 1024 * 100) / 100.0);
        }
        return 0;
    }

}
