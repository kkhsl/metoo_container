package com.metoo.nspm.core.utils.collections;

        import org.springframework.stereotype.Component;

        import java.util.*;

@Component
public class ListSortUtil {

    public static void compareTo(List<Map<Object, Object>> list){
        Collections.sort(list, new Comparator<Map<Object, Object>>() {
            @Override
            public int compare(Map<Object, Object> o1, Map<Object, Object> o2) {
                String key1 = o1.get("policyCheckTotal").toString();
                String key2 = o2.get("policyCheckTotal").toString();
                return key2.compareTo(key1);
            }
        });
    }

    public static void sort(List<Map<String, Double>> list){
        Collections.sort(list, new Comparator<Map<String, Double>>() {
            @Override
            public int compare(Map<String, Double> o1, Map<String, Double> o2) {
                Double key1 = o1.get("grade");
                Double key2 = o2.get("grade");
                return key1.compareTo(key2);
            }
        });
    }

    /**
     * 英文数字组合排序
     * @param list
     */
    public static void sortStr(List<Map<String, Object>> list){
        Collections.sort(list, new Comparator<Map<String, Object>>() {
            @Override
            public int compare(Map<String, Object> o1, Map<String, Object> o2) {
                String key1 = o1.get("name").toString();

                key1 = key1.replaceAll("/", "");
                key1 = key1.replaceAll("-", "");

                String o1_num = key1.replaceAll("[a-zA-Z]", "");

                key1 = key1.replaceAll("\\.", "");
                String o1_str = key1.replaceAll("[0-9]", "");

                String key2 = o2.get("name").toString();

//                key2 = key2.replaceAll("[a-zA-Z]", "");
                key2 = key2.replaceAll("/", "");
                key2 = key2.replaceAll("-", "");

                String o2_num = key2.replaceAll("[a-zA-Z]", "");

                key2 = key2.replaceAll("\\.", "");
                String o2_str = key2.replaceAll("[0-9]", "");


                int n = 0;
                if(!o1_str.equals(o2_str)){
                    n = o1_str.compareTo(o2_str);
                }
                if(o1_num.equals("") || o2_num.equals("")){
                    return n;
                }
                double i = Double.parseDouble(o1_num);
                double j = Double.parseDouble(o2_num);
                int m = 0;
                if(n == 0){
                    m = i > j ? 1:-1;
                    return m;
                }else{
                    return n;
                }
            }
        });
    }

    public static void intSort(List<Map<String, Object>> list){
        Collections.sort(list, new Comparator<Map<String, Object>>() {
            @Override
            public int compare(Map<String, Object> o1, Map<String, Object> o2) {
                int key1 = Integer.parseInt(o1.get("level").toString());
                int key2 = Integer.parseInt(o2.get("level").toString());
                return key1 < key2 ? 1 : -1; // 降序
            }
        });
    }

    public static void main(String[] args) {

        List<String> list = new ArrayList();
        list.add("G-E100");
        list.add("GE103");
        list.add("GE101");
        list.add("GES1012");
        list.add("GsES101");
        list.add("G00");
        list.add("GE000");
        list.add("GE1021");
        list.add("GE102");
        ListSortUtil.sortStr1(list);
        System.out.println(list);
    }

    public static void sortStr1(List<String> list){
        Collections.sort(list, new Comparator<String>() {
            @Override
            public int compare(String o1,String o2) {

                o1 = o1.replaceAll("/", "");

                String o1_num = o1.replaceAll("[a-zA-Z]", "");

                String o1_str = o1.replaceAll("[0-9]", "");

                o2 = o2.replaceAll("/", "");

                String o2_num = o2.replaceAll("[a-zA-Z]", "");

                String o2_str = o2.replaceAll("[0-9]", "");

                int n = 0;
                if(!o1_str.equals(o2_str)){
                    n = o2_str.length() - o1_str.length();
                }
                if(o1_num.equals("")){

                }
                if(o2_num.equals("")){

                }
                int i = Integer.parseInt(o1_num);

                int j = Integer.parseInt(o2_num);
                int m = 0;
                if(n == 0){
                    m = i > j ? 1:-1;
                    return m;
                }else{
                    return n;
                }


//                int i = Integer.parseInt(key1);

//                int j = Integer.parseInt(key2);

//                return i > j ? 1:-1;//这里返回的值，1升序 -1降序
            }
        });
    }

//    public static void sortByIp(List<Arp> list){
//        Collections.sort(list, new Comparator<Arp>() {
//            @Override
//            public int compare(Arp arp1, Arp arp2) {
//                String ip1 = arp1.getIp();
//                String ip2 = arp2.getIp();
//                return key1.compareTo(key2);
//            }
//        });
//    }

    public static void lambdaSort(List<Map<String, Double>> list){
        Collections.sort(list, (s1, s2) -> s1.get("grade").compareTo(s2.get("grade")));
    }


}
