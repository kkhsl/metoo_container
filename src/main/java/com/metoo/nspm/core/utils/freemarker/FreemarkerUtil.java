package com.metoo.nspm.core.utils.freemarker;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.*;

@Component
public class FreemarkerUtil {

    public static void main(String[] args) {
        String path = Thread.currentThread().getContextClassLoader().getResource("").getPath();
        System.out.println(path);
    }

    private static Configuration config;
    private static String serverPath;

    @Value("${spring.servlet.multipart.location:D:\\java\\project\\metoo\\freeMarker\\}")
    public void setServerPath(String serverPath) {
        FreemarkerUtil.serverPath = serverPath;
    }

    /**
     *
     * @param templateName 模板名称
     * @param targetFileName 生成html文件名
     * @param ftlPath 模板路径
     * @param htmlPath html路径
     * @param object 数据
     */
    public void createHtml(String templateName, String targetFileName, Object object){
        //创建fm的配置
        config = new Configuration();
        //指定默认编码格式
        config.setDefaultEncoding("UTF-8");
        //设置模版文件的路径
        try {
            config.setDirectoryForTemplateLoading(new File(serverPath));
            //获得模版包
            Template template = config.getTemplate(templateName);
            //从参数文件中获取指定输出路径
            String path = serverPath;

            //生成的静态页存放路径如果不存在就创建
            File file = null;
            file=new File(path);
            if (!file.exists()){
                file.mkdirs();
            }
            //定义输出流，注意必须指定编码
            Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File(path+"/"+targetFileName))));
            //生成模版
            template.process(object, writer);

        } catch (IOException e) {
            e.printStackTrace();
        } catch (TemplateException e) {
            e.printStackTrace();
        }

    }
}
