package com.metoo.nspm.core.video;

import java.io.*;

/**
 * <p>
 *     Title: TestMerge.class
 * </p>
 *
 * <p>
 *     Description: 合并ts文件
 * </p>
 *
 * <author>
 *     HKk  1
 *
 * </author>
 */
public class TestMerge {

    public static void main(String[] args) throws FileNotFoundException {
                BufferedInputStream bis;
                BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("C:\\Users\\46075\\Desktop\\20210323040120436\\merge.ts"));
                for (int x=320;x<=400;x++) {
                    try {
                        bis = new BufferedInputStream(new FileInputStream("C:\\Users\\46075\\Desktop\\20210323040120436\\" + x + ".ts"));
                        byte[] by = new byte[1024];
                        int len;
                        while((len=bis.read(by))!=-1)
                        {
                            bos.write(by,0,len);
                            bos.flush();
                        }
                    } catch (FileNotFoundException e) {

            } catch (IOException e) {
                throw new RuntimeException("第"+x+"次循环IO流异常");
            }
        }
    }
}
