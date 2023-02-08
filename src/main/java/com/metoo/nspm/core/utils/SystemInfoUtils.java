package com.metoo.nspm.core.utils;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

@Component
public class SystemInfoUtils {

    public String getBiosUuid() {
        String cpuId = null;
        // 获取当前操作系统名称
        String os = System.getProperty("os.name");
        os = os.toUpperCase();
        if ("LINUX".equals(os)) {
            try {
                cpuId = getLinuxDmidecodeInfo("dmidecode -t system | grep 'UUID'", "UUID", ":");
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            try {
                cpuId = getWindowsBiosUUID();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return cpuId.toUpperCase().replace(" ", "");
    }

    /**
     * 获取linux系统
     * dmidecode
     * 命令的信息
     */
    public static String getLinuxDmidecodeInfo(String cmd, String record, String symbol) throws IOException {
        String execResult = executeLinuxCmd(cmd);
        String[] infos = execResult.split("\n");
        for (String info : infos) {
            info = info.trim();
            if (info.contains(record)) {
                info.replace(" ", "");
                String[] sn = info.split(symbol);
                return sn[1];
            }
        }
        return null;
    }


    /**
     * 执行Linux 命令
     *
     * @param cmd Linux 命令
     * @return 命令结果信息
     * @throws IOException 执行命令期间发生的IO异常
     */
    public static String executeLinuxCmd(String cmd) throws IOException {
        Runtime run = Runtime.getRuntime();
        Process process;
        process = run.exec(cmd);
        InputStream processInputStream = process.getInputStream();
        StringBuilder stringBuilder = new StringBuilder();
        byte[] b = new byte[8192];
        for (int n; (n = processInputStream.read(b)) != -1; ) {
            stringBuilder.append(new String(b, 0, n));
        }
        processInputStream.close();
        process.destroy();
        return stringBuilder.toString();
    }

    /**
     * 获取windows系统 bios uuid
     *
     * @return
     * @throws IOException
     */
    public static String getWindowsBiosUUID() throws IOException {
        Process process =Runtime.getRuntime().exec(new  String[]{"wmic","bios","get","serialnumber"});
        process.getOutputStream().close();
        Scanner sc = new Scanner(process.getInputStream());
        sc.next();
        String serial = sc.next();
        return serial;
    }
}
