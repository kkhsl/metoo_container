package com.metoo.nspm.core.utils.DataStructure;

/**
 * 自定义Enum
 */
enum MyEnum {

    SPRING("春天", "春意盎然"),
    SUMMER("夏天", "夏日炎炎"),
    AUTUMN("秋天", "秋高气爽"),
    WINTER("冬天", "白雪皑皑");


    private final String seasonName;
    private final String seasonDesc;

    private MyEnum(String seasonName, String SeasonDesc){
        this.seasonName=seasonName;
        this.seasonDesc=SeasonDesc;
    }

    @Override
    public String toString() {
        return "MyEnum{" +
                "seasonName='" + seasonName + '\'' +
                ", seasonDesc='" + seasonDesc + '\'' +
                '}';
    }
}

class MyTest{
    public static void main(String[] args) {
        // 1 toString方法测试：调用默认的toString方法，可自己重写String方法
        MyEnum autumn = MyEnum.AUTUMN;
        System.out.println(autumn);

        // 2 values方法测试
        MyEnum[] values = MyEnum.values();
        for (MyEnum value : values) {
            System.out.println(value);
        }

        // 3 valueOf方法测试。字符串必须是枚举类的名字，区分大小写
        MyEnum spring = MyEnum.valueOf("SPRING");
        System.out.println(spring);

    }
}
