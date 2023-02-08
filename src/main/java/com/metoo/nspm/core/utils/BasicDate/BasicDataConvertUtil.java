package com.metoo.nspm.core.utils.BasicDate;

import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.text.DecimalFormat;
import java.text.NumberFormat;

@Component
public class BasicDataConvertUtil {

    /**
     *  ROUND_CEILING  接近正无穷大的舍入模式。
     *  ROUND_DOWN  从不对舍弃部分前面的数字加1，即截短。
     *  ROUND_FLOOR  接近负无穷大的舍入模式。
     *  ROUND_HALF_DOWN  向“最接近的”数字舍入，如果与两个相邻数字的距离相等，则为上舍入的舍入模式。
     *  ROUND_HALF_EVEN  向“最接近的”数字舍入，如果与两个相邻数字的距离相等，则向相邻的偶数舍入。
     *  ROUND_HALF_UP  向“最接近的”数字舍入，如果与两个相邻数字的距离相等，则为向上舍入的舍入模式。
     *  ROUND_UNNECESSARY  断言请求的操作具有精确的结果，因此不需要舍入(如果对获得精确结果的操作指定此舍入模
     *  式，则抛出ArithmeticException)。
     *  ROUND_UP  始终对非舍弃部分前面的数字加1。
     * @param args
     */
    public static void main(String[] args) {
//        double i = 0.48548076923076934;
//        double ii = BasicDataConvertUtil.formatDouble(i);
//        System.out.println(ii);
//        System.out.println(BasicDataConvertUtil.bigDecimalFormat(BasicDataConvertUtil.formatDouble(i)));

        double i  = 670390453;
        double j = i / 1000000;
        System.out.println(j);
        System.out.println(BasicDataConvertUtil.bigDecimalFormat(BasicDataConvertUtil.formatDouble(j)));
    }

    public static double formatDouble(double d) {
        return (double)Math.round(d * 100) / 100;
    }

    /**
     * 保留小数位
     * @param data
     * @return
     */
    public static double bigDecimalSetScale(double data){
        BigDecimal two = new BigDecimal(data);
        double result = two.setScale(2,BigDecimal.ROUND_HALF_UP).doubleValue();
        return result;
    }

    /**
     * 保留小数位
     * @param data
     * @return
     */
    public static double bigDecimalFormat(double data){
        DecimalFormat format = new DecimalFormat("#.00");
        String str = format.format(data);
        double result = Double.parseDouble(str);
        return result;
    }

    public static double stringFormat(double data){
        String str = String.format("%.2f",data);
        double result = Double.parseDouble(str);
        return result;
    }


}
