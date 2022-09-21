package burp.Bootstrap;

import burp.IBurpExtenderCallbacks;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class YamlReader {
    private static YamlReader instance;

    private static Map<String, Map<String, Object>> properties = new HashMap<>();

    private YamlReader(IBurpExtenderCallbacks callbacks) throws FileNotFoundException {
        CustomBurpHelpers customBurpHelpers = new CustomBurpHelpers(callbacks);
        String c = customBurpHelpers.getExtensionFilePath() + "resources/config.yml";
        File f = new File(c);
        properties = new Yaml().load(new FileInputStream(f));
    }

    //有参构造器私有化，通过该方法获取YamlReader实例并保存在instance，下次使用直接拿instance
    public static synchronized YamlReader getInstance(IBurpExtenderCallbacks callbacks){
        if (instance == null){
            try{
                instance = new YamlReader(callbacks);
            } catch (FileNotFoundException e) {
                e.printStackTrace(new PrintWriter(callbacks.getStderr(), true));
            }
        }
        return instance;
    }

    //获取yaml属性值
    public static Object getValueByKey(String key){
        String separator = ".";
        String[] separatorKeys = null;
        if (key.contains(separator)){
            separatorKeys = key.split("\\.");
        }else {
            return properties.get(key);
        }

        Map<String, Map<String, Object>> finalValue = new HashMap<>();
        for (int i = 0; i < separatorKeys.length-1; i++) {
            if (i == 0){
                finalValue = (Map) properties.get(separatorKeys[i]);
                continue;
            }
            if (finalValue == null) {
                break;
            }
            finalValue = (Map)finalValue.get(separatorKeys[i]);
        }
        return finalValue == null ? null : finalValue.get(separatorKeys[separatorKeys.length - 1]);
    }

    public String getString(String key) {
        return String.valueOf(this.getValueByKey(key));
    }

    public Boolean getBoolean(String key) {
        return (boolean) this.getValueByKey(key);
    }

    public Integer getInteger(String key) {
        return (Integer) this.getValueByKey(key);
    }

    public double getDouble(String key) {
        return (double) this.getValueByKey(key);
    }

    public List<String> getStringList(String key) {
        return (List<String>) this.getValueByKey(key);
    }
}
