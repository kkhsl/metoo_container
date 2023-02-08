package com.metoo.nspm.core.utils.quartz;

import lombok.experimental.var;
import org.joda.time.DateTime;

import javax.persistence.Convert;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;

/**
 * Timer：Java自带的定时任务类（java.util.*）
 *
 * 优点：使用简单
 * 缺点：添加并执行多个任务时，前面的任务执行用时和异常将会影响到后面的任务（谨慎使用）
 *
 */
public class MyTimeTask {

    /**
     * 待测试：任务执行时间超过任务间隔；插入数据库是否会有影响
     * @param args
     */
    public static void main(String[] args) {
        TimerTask timerTask = new TimerTask() {
            @Override
            public void run() {
                System.out.println("打印当前时间：" + new Date());
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        };
        // 计时器
        Timer timer = new Timer();
        // 开始执行（模拟延迟1000毫秒后执行，每3000毫秒执行一次）
        timer.schedule(timerTask, 5000, 3000);
    }

//    /// <summary>
//    /// 执行定时器（每天定时19点执行相应方法）
//    /// </summary>
//    public static void ExecutionTimer()
//    {
//        DateTime executionTime = Convert.ToDateTime($"{DateTime.Now:yyyy-MM-dd} 19:00:00");
//
//        DateTime nowTime = DateTime.Now;
//
//        var timeSpan = (executionTime - nowTime).TotalMilliseconds;
//
//        var interval = timeSpan >= 0 ? timeSpan + 1 : (12 * 60 * 60 * 1000) + timeSpan;
//
//        // 重启网站时，如果此时的时间距离定时器执行的时间间隔大于30分钟，则执行相应方法
//        if (timeSpan > 30 * 60 * 1000 || (timeSpan < -1 * 30 * 60 * 1000 && timeSpan < 0))
//        {
//            ExecutionMethod();
//        }
//
//        System.Timers.Timer timer = new System.Timers.Timer(interval) { AutoReset = false, Enabled = true };
//
//        timer.Elapsed += (o, e) =>
//        {
//            ExecutionMethod();
//
//            System.Timers.Timer newTimer = new System.Timers.Timer(12 * 60 * 60 * 1000) { AutoReset = true, Enabled = true };
//
//            newTimer.Elapsed += (newO, newE) =>
//            {
//                ExecutionMethod();
//            };
//
//            newTimer.Start();
//        };
//
//        timer.Start();
//    }

}
