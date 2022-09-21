import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class Test1 {
    public static void main(String[] args) throws IOException {
//        BufferedReader in = new BufferedReader(new FileReader("D:\\tools\\shiro_detect\\src\\main\\resources\\shiroKey.txt"));
//        String str;
//        String str1 = "";
//        while ((str = in.readLine()) != null) {
//            str1 += str.trim()+"\n";
//        }
//        System.out.println(str1);

        File file = new File("D:\\tools\\shiro_detect\\target\\BurpShiroPassiveScan\\resources\\shiroKey.txt");
        Long filelength = file.length();     //获取文件长度
        byte[] filecontent = new byte[filelength.intValue()];
        try {
            FileInputStream in = new FileInputStream(file);
            in.read(filecontent);
            in.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        String payload = new String(filecontent);
        List<String> strings = new ArrayList<String>(Arrays.asList(payload.split("\r\n")));
        strings.removeAll(Arrays.asList("", null));



    }
}
