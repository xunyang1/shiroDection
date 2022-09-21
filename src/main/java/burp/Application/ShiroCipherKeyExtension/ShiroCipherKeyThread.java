package burp.Application.ShiroCipherKeyExtension;

import burp.Application.ShiroFingerprintExtension.ShiroFingerprint;
import burp.Bootstrap.*;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ShiroCipherKeyThread {
    private List<Thread> threadPool = new ArrayList<>();

    public ShiroCipherKeyThread(GlobalVariableReader globalVariableReader,
                                GlobalPassiveScanVariableReader globalPassiveScanVariableReader,
                                IBurpExtenderCallbacks callbacks,
                                YamlReader yamlReader,
                                IHttpRequestResponse baseRequestResponse,
                                ShiroFingerprint shiroFingerprint,
                                String callClassName){
        //任务线程通过检查这个字段是否为true，来判断是否已经爆破出key
        globalPassiveScanVariableReader.putBooleanData("isEndShiroCipherKeyTask", false);

        if (callClassName == null || callClassName.length() <= 0) {
            throw new IllegalArgumentException("Application.ShiroCipherKeyExtension-请输入要调用的插件名称");
        }

        Integer threadCount = yamlReader.getInteger("webSite.shiroCipherKeyDetection.config.threadCount");
        if (threadCount == 0) {
            throw new IllegalArgumentException("Application.ShiroCipherKeyExtension-获取的线程数为0,无法正常运行");
        }


//        List<String> payloads = yamlReader.getStringList("webSite.shiroCipherKeyDetection.config.payloads");
//        if (payloads.size() == 0) {
//            throw new IllegalArgumentException("Application.ShiroCipherKeyExtension-获取的payloads为空,无法正常运行");
//        }

        List<String> payloads = new CustomBurpHelpers(callbacks).getPayloadList();


        //将payloads按线程数分组，然后分配给不同线程
        List<List<String>> payloadChunk = CustomHelpers.listChunkSplit(payloads, threadCount);

        for (List<String> payloadList : payloadChunk) {
            this.threadPool.add(new Thread(
                    new ShiroCipherKey(globalVariableReader, globalPassiveScanVariableReader, callbacks, yamlReader,
                            baseRequestResponse, shiroFingerprint, callClassName, payloadList)
            ));
        }

        // 线程启动
        for (int i = 0; i < this.threadPool.size(); i++) {
            this.threadPool.get(i).start();
        }
    }

    public Boolean isTaskComplete(){
        //总线程数
        int size = this.threadPool.size();

        //计算已完成线程数
        int num = 0;
        for (Thread thread : threadPool) {
            if (!thread.isAlive()){
                num++;
            }
        }

        if (num == size){
            return true;
        }

        return false;
    }
}
