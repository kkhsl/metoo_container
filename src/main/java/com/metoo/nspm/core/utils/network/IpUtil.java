package com.metoo.nspm.core.utils.network;

import com.github.pagehelper.util.StringUtil;
import org.apache.commons.net.util.SubnetUtils;
import org.junit.Test;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.regex.Pattern;

@Component
public class IpUtil {

    private static Long ipv4ToNumeric(String ip) {
        Scanner sc = new Scanner(ip).useDelimiter("\\.");
        Long restValue = (sc.nextLong() << 24) + (sc.nextLong() << 16) + (sc.nextLong() << 8) + (sc.nextLong());
        sc.close();
        return restValue;
    }

    @Test
    public void test(){
        // 主机数
        long maxRange = (long)0x1<<(32 - 24);
        System.out.println("主机数：" + maxRange);

        SubnetUtils utils = new SubnetUtils("192.168.1.0/24");
        String[] allIps = utils.getInfo().getAllAddresses();
        System.out.println(allIps);

        this.getSubnetList("192.168.1.0", 0);
    }

    @Test// ip转十进制
    public void test1(){
        String[] split = "59.51.0.1".split("\\.");
        Long rs=0L;
        for(int i=0,j=split.length-1;i<split.length;j--,i++){
//            System.out.println(split[i]);
            Long intIp=Long.parseLong(split[i]) << 8 * j;
            rs=rs | intIp;
        }
        System.out.println(rs);  //3232235777
    }

    @Test// 验证ip
    public void test2(){
        boolean flag = verifyIp("127.0.0.0");
        System.out.println(flag);
        boolean f = Pattern.matches("^([1-9]|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3}$", "0.0.0.0");
        System.out.println(f);
    }

    // 验证ip是否为网段
    @Test
    public void test3(){
//        Map map = getNetworkIp("59.51.0.1", "255.255.255.0");
//        System.out.println(map);
    }


    // 验证ip是否为
    @Test
    public void test4(){
        boolean flag = ipIsInNet("59.51.1.0", "59.51.0.0/24");
        System.out.println(flag);
    }

    private static BigInteger ipv6ToNumeric(String ip) {
        BigInteger ipNum = null;
        try {
            ipNum = new BigInteger(1, InetAddress.getByName(ip).getAddress());
        } catch (UnknownHostException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return ipNum;
    }

    public static Map<String, SortedSet<String>> ipSort(List<String> ips) {
        List<String> ipv4 = new ArrayList<>();
        List<String> ipv6 = new ArrayList<>();
        List<String> uncertain = new ArrayList<>();
        Map<String, SortedSet<String>> restMap = new HashMap<>(3);

        for (String ip : ips) {
            if (ip.contains(":")) {
                ipv6.add(ip);
            } else if (ip.contains(".")) {
                ipv4.add(ip);
            } else {
                System.out.println("不属于ipv4或者ipv6： " + ip);
                uncertain.add(ip);
            }
        }

        // ipv4排序
        Comparator<String> ipv4Comparator = Comparator.comparing(IpUtil::ipv4ToNumeric);
        SortedSet<String> rest_ipv4 = new TreeSet<>(ipv4Comparator);
        rest_ipv4.addAll(ipv4);
        restMap.put("ipv4", rest_ipv4);

        // ipv6排序
        Comparator<String> ipv6Comparator = Comparator.comparing(IpUtil::ipv6ToNumeric);
        SortedSet<String> rest_ipv6 = new TreeSet<>(ipv6Comparator);
        rest_ipv6.addAll(ipv6);
        restMap.put("ipv4", rest_ipv6);

        // 返回排序结果
        return restMap;
    }

    /**
     * 判断ip是否在指定网段
     *
     * @param ip
     * @return
     */
    public static boolean ipIsInNet(String ip, String ipArea) {
//        if ("127.0.0.1".equals(ip)) {
//            return true;
//        }
//
//        if(StringUtils.isBlank(ipArea)){
//            return false;
//        }

        String[] ipArray = ipArea.split(",");
        for (String s : ipArray) {
            if (!s.contains("/")) {
                if (s.equals(ip)) {
                    return true;
                }
                continue;
            }

            String[] ips = ip.split("\\.");
            //ip地址的十进制值
            int ipAddress = (Integer.parseInt(ips[0]) << 24)
                    | (Integer.parseInt(ips[1]) << 16)
                    | (Integer.parseInt(ips[2]) << 8) | Integer.parseInt(ips[3]);
            //掩码（0-32）
            int type = Integer.parseInt(s.replaceAll(".*/", ""));
            //匹配的位数为32 - type位（16进制的1）
            int mask = 0xFFFFFFFF << (32 - type);
            String cidrIp = s.replaceAll("/.*", "");
            //网段ip十进制
            String[] cidrIps = cidrIp.split("\\.");
            int cidrIpAddr = (Integer.parseInt(cidrIps[0]) << 24)
                    | (Integer.parseInt(cidrIps[1]) << 16)
                    | (Integer.parseInt(cidrIps[2]) << 8)
                    | Integer.parseInt(cidrIps[3]);

            if((ipAddress & mask) == (cidrIpAddr & mask)){
                return true;
            }
            continue;
        }
        return false;
    }

    public static boolean verifyIp(String ip){
        String regex = "^(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[1-9])\\."
                + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\." +"(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
                + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)$";
        // 判断ip地址是否与正则表达式匹配
        if (!ip.matches(regex)) {
            return false;
        }
        return true;
    }

    /**
     * ip地址转十进制
     * @param
     */
    public static String ipConvertDec(String ip){
//        String ip="192.168.1.1";
        if(ip == null || ip.equals("")){
            return null;
        }
        if(ip.equals("0.0.0.0")){

        }else{
            boolean isIp = verifyIp(ip);
            if(!isIp){
                return null;
            }
        }
        String[] split = ip.split("\\.");
        Long rs=0L;
        for(int i=0,j=split.length-1;i<split.length;j--,i++){
            Long intIp=Long.parseLong(split[i]) << 8 * j;
            rs=rs | intIp;
        }
        return rs.toString();
    }

    /**
     * 十进制转ip
     */
    public static String decConvertIp(Long rs){
//        Long rs=3232235777L;
        String[] ipString = new String[4];
        for (int i = 0,j=3; i <4; j--,i++) {
            // 每 8 位为一段，这里取当前要处理的最高位的位置
            int pos = i * 8;
            // 取当前处理的 ip 段的值   rs=3232235777
            long and = rs & (255 << pos);
            // 将当前 ip 段转换为 0 ~ 255 的数字，注意这里必须使用无符号右移
            ipString[j] = String.valueOf(and >>> pos);
        }
        String join = String.join(".", ipString);
        return join;
    }

    /**
     *
     * @param mask
     * @return
     */
    public static int getHostNum(Integer mask){
        if(mask != null){
            int number = (int) Math.pow(2, 32 - mask);
            return number;
        }
        return 0;
    }

    // 获取网络地址
    public static Map<String, String> getNetworkIp(String address, String netmask){
        Map<String, String> map = new HashMap<String, String>();
        String network = new String();
        String broadcast = new String();
        String[] addresses = address.split("\\.");
        String[] masks = netmask.split("\\.");
        for(int i = 0; i < 4; i++) {
            int opmasksegement = ~Integer.parseInt(masks[i]) & 0xFF;
            //此处有坑，正常的int有32位，
            // 如果此数没有32位的话，就会用0填充前面的数，
            // 从而导致取反0的部分会用1来填充，
            // 用上述方法可以获取想要的部分
            int netsegment = Integer.parseInt(addresses[i]) & Integer.parseInt(masks[i]);
            network = network + String.valueOf(netsegment) + ".";
            broadcast = broadcast + String.valueOf(opmasksegement | netsegment) + ".";
        }
        map.put("network", network.substring(0, network.length() - 1));
        map.put("broadcast", broadcast.substring(0, broadcast.length() - 1));
        return map;
    }

    // 获取网络地址
    public static Map<String, String> getNetworkIpDec(String address, String netmask){
        Map<String, String> map = new HashMap<String, String>();
        String network = new String();
        String broadcast = new String();
        String[] addresses = address.split("\\.");
        String[] masks = netmask.split("\\.");
        for(int i = 0; i < 4; i++) {
            int opmasksegement = ~Integer.parseInt(masks[i]) & 0xFF;
            //此处有坑，正常的int有32位，
            // 如果此数没有32位的话，就会用0填充前面的数，
            // 从而导致取反0的部分会用1来填充，
            // 用上述方法可以获取想要的部分
            int netsegment = Integer.parseInt(addresses[i]) & Integer.parseInt(masks[i]);
            network = network + String.valueOf(netsegment) + ".";
            broadcast = broadcast + String.valueOf(opmasksegement | netsegment) + ".";
        }
        network = ipConvertDec(network.substring(0, network.length() - 1));
        broadcast = ipConvertDec(broadcast.substring(0, broadcast.length() - 1));
        map.put("network", network);
        map.put("broadcast", broadcast);
        return map;
    }


    /**
     * 获取网络地址
     * @param ip
     * @param netmask
     * @return
     */
    public static Map getNetworkIpAddress(String ip, String netmask){
        Map<String, String> map = new HashMap<String, String>();
        String network = new String();
        String broadcast = new String();
        String[] addresses = ip.split("\\.");
        String[] masks = netmask.split("\\.");
        for(int i = 0; i < 4; i++) {
            int opmasksegement = ~Integer.parseInt(masks[i]) & 0xFF;
            //此处有坑，正常的int有32位，
            // 如果此数没有32位的话，就会用0填充前面的数，
            // 从而导致取反0的部分会用1来填充，
            // 用上述方法可以获取想要的部分
            int netsegment = Integer.parseInt(addresses[i]) & Integer.parseInt(masks[i]);
            network = network + String.valueOf(netsegment) + ".";
            broadcast = broadcast + String.valueOf(opmasksegement | netsegment) + ".";
        }
        network = ipConvertDec(network.substring(0, network.length() - 1));
        broadcast = ipConvertDec(broadcast.substring(0, broadcast.length() - 1));
        map.put("network", network);
        map.put("broadcast", broadcast);
        return map;
    }

    /**
     * 获取广播地址
     * @param ip 192.168.0.0
     * @param netmask 255.255.255.0
     * @param type 0：网络地址 1：广播地址
     * @return 默认返回主机地址
     */
    public static String getNBIP(String ip, String netmask, Integer type){
        Map<String, String> map = new HashMap<String, String>();
        String network = new String();
        String broadcast = new String();
        String[] addresses = ip.split("\\.");
        String[] masks = netmask.split("\\.");
        for(int i = 0; i < 4; i++) {
            int opmasksegement = ~Integer.parseInt(masks[i]) & 0xFF;
            //此处有坑，正常的int有32位，
            // 如果此数没有32位的话，就会用0填充前面的数，
            // 从而导致取反0的部分会用1来填充，
            // 用上述方法可以获取想要的部分
            int netsegment = Integer.parseInt(addresses[i]) & Integer.parseInt(masks[i]);
            network = network + String.valueOf(netsegment) + ".";
            broadcast = broadcast + String.valueOf(opmasksegement | netsegment) + ".";
        }
        network = ipConvertDec(network.substring(0, network.length() - 1));
        broadcast = ipConvertDec(broadcast.substring(0, broadcast.length() - 1));
        map.put("network", network);
        map.put("broadcast", broadcast);
        if(type  == 0){
            return network;
        }else
        if(type == 1){
            return broadcast;
        }
        return network;
    }


    // 获取子网列表
    public  static String[] getSubnetList(String ip, int mask){
        if(!StringUtil.isEmpty(ip) && mask >= 1 && mask <= 32){
            SubnetUtils utils = new SubnetUtils(ip + "/" +  mask);
            String[] allIps = utils.getInfo().getAllAddresses();
            return allIps;
        }
        return null;
    }

    /**
     * 掩码转掩码位：方式一
     * @param mask
     * @return
     */
    public static int getMaskBitMask(String mask){
        StringBuffer sbf;
        String str;
        int inetmask = 0, count = 0;
        if(StringUtil.isEmpty(mask)){
            return inetmask;
        }
        String[] ipList = mask.split("\\.");
        for (int n = 0; n < ipList.length; n++) {
            sbf = toBin(Integer.parseInt(ipList[n]));
            str = sbf.reverse().toString();

            // 统计2进制字符串中1的个数
            count = 0;
            for (int i = 0; i < str.length(); i++) {
                i = str.indexOf('1', i); // 查找 字符'1'出现的位置
                if (i == -1) {
                    break;
                }
                count++; // 统计字符出现次数
            }
            inetmask += count;
        }
        return inetmask;
    }

    public static StringBuffer toBin(int x) {
        StringBuffer result = new StringBuffer();
        result.append(x % 2);
        x /= 2;
        while (x > 0) {
            result.append(x % 2);
            x /= 2;
        }
        return result;
    }

    /**
     * 掩码 转 掩码位：方式二
     * @param
     */
    public static String getBitMask(String mask){
        String stdMask = "";
        String[] masks = mask.split("\\.");
        for (String item : masks) {
            String temp = Integer.toBinaryString(Integer.parseInt(item));
            stdMask = stdMask + temp;
        }
        stdMask = stdMask.replace("0", "").length() + "";
        return stdMask;
    }

    public static String bitMaskConvertMask(int x){
        int ip = 0xFFFFFFFF << (32 - x);
        String binaryStr = Integer.toBinaryString(ip);
        StringBuffer buffer = new StringBuffer();
        for (int j = 0; j < 4; j++) {
            int beginIndex = j * 8;
            buffer.append(Integer.parseInt(binaryStr.substring(beginIndex, beginIndex + 8), 2)).append(".");
        }
        return buffer.substring(0, buffer.length() - 1);
    }

    //取反掩码
    private static String ConvertToMask(String mask) {
        String cmasn = "";
        String[] reMasks = mask.split("\\.");
        for (String item : reMasks) {
            int temp = 255 - Integer.parseInt(item);
            cmasn = cmasn + temp + ".";
        }
        return cmasn.substring(0, cmasn.length() - 1);
    }


    /**
     *
     * @param bitMask
     * @return
     */
    public static String getMaskList(Integer bitMask){
//        for(int i=1;i<bitMask;i++) {
            int ip = 0xFFFFFFFF << (32 - bitMask);
            String binaryStr = Integer.toBinaryString(ip);
            StringBuffer buffer = new StringBuffer();
            for (int j = 0; j < 4; j++) {
                int beginIndex = j * 8;
                buffer.append(Integer.parseInt(binaryStr.substring(beginIndex, beginIndex + 8), 2)).append(".");
            }
            return buffer.substring(0, buffer.length() - 1).toString();
//            System.out.println("net mask " + i + " ,submask:" + buffer.substring(0, buffer.length() - 1));
//        }
    }



}
