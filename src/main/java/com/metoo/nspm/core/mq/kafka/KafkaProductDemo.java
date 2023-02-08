package com.metoo.nspm.core.mq.kafka;

//import org.apache.kafka.clients.producer.*;
//import org.apache.kafka.common.serialization.StringSerializer;

import java.util.concurrent.ExecutionException;

public class KafkaProductDemo {

    private final static String TOPIC_NAME = "my-replicated-topic";

    public static void main(String[] args)throws ExecutionException, InterruptedException {
//        Properties props = new Properties();
//        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG,"0.0.0.0:00,0.0.0.0:00,0.0.0.0:00");
//        // 把发送的key从字符串序列中转化为字节数组
//        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
//        // 把发送的消息value从字符串序列转化为字节数组
//        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
//
//        Producer<String, String> producer = new KafkaProducer<String, String>(props);
//        KafkaOrder order = new KafkaOrder();// (long)i, i
//        ProducerRecord<String, String> producerRecord = new ProducerRecord<String, String>(TOPIC_NAME, order.getOrderId().toString(), JSON.toJSONString(order));
//        // 等待消息发送成功的同步阻塞方法
//        RecordMetadata metadata = producer.send(producerRecord).get();
//        // ====== 阻塞 ======
//        System.out.println("同步方式发送消息结果：" + "topic-" + metadata.topic() + "|patition-"
//                + metadata.partition() + "|offset-" + metadata.offset());
    }
}
