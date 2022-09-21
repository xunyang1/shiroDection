package burp.Bootstrap;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IResponseInfo;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CustomBurpHelpers {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private File payloadFile;

    public CustomBurpHelpers(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.payloadFile = new File(this.getExtensionFilePath() + "resources/shiroKey.txt");
    }

    //获取插件运行路径
    public String getExtensionFilePath() {
        String path = "";
        Integer lastIndex = this.callbacks.getExtensionFilename().lastIndexOf(File.separator);
        path = this.callbacks.getExtensionFilename().substring(0, lastIndex) + File.separator;
        return path;
    }

    public List<String> getPayloadList() {
        Long filelength = this.payloadFile.length();     //获取文件长度
        byte[] filecontent = new byte[filelength.intValue()];
        try {
            FileInputStream in = new FileInputStream(this.payloadFile);
            in.read(filecontent);
            in.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        String payload = new String(filecontent);
        List<String> payloadList = new ArrayList<String>(Arrays.asList(payload.split("\r\n")));
        payloadList.removeAll(Arrays.asList("", null));
        return payloadList;
    }

    public boolean addPayloadList(List<String> payloadList) {
        FileWriter fileWriter = null;
        BufferedWriter bufferedWriter = null;
        payloadList.add(0, "");

        try {
            //创建输出流
            fileWriter = new FileWriter(this.payloadFile, true);//true代表追加写入内容至文件末尾
            bufferedWriter = new BufferedWriter(fileWriter);

            //输出
            for (String payload : payloadList) {
                bufferedWriter.write(payload + "\r\n");
            }
            return true;
        } catch (Exception e){
            e.printStackTrace(new PrintWriter(callbacks.getStderr(), true));
        } finally {
            if (bufferedWriter != null){
                try {
                    bufferedWriter.close();
                }catch (Exception e){
                    e.printStackTrace(new PrintWriter(callbacks.getStderr(), true));
                }

            if (fileWriter != null){
                try {
                    fileWriter.close();
                }catch (Exception e){
                    e.printStackTrace(new PrintWriter(callbacks.getStderr(), true));
                }
            }
            }
        }
        return false;
    }


    /**
     * 获取响应的Body内容
     *
     * @return String
     */
    public String getHttpResponseBody(byte[] response) {
        IResponseInfo responseInfo = this.helpers.analyzeResponse(response);

        int httpResponseBodyOffset = responseInfo.getBodyOffset();
        int httpResponseBodyLength = response.length - httpResponseBodyOffset;

        String httpResponseBody = null;
        try {
            httpResponseBody = new String(response, httpResponseBodyOffset, httpResponseBodyLength, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        return httpResponseBody;
    }
}
