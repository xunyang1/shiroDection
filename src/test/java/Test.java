import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.Map;

public class Test {
    private static Map<String, Map<String, Object>> properties = new HashMap<>();
    public static void main(String[] args) throws FileNotFoundException {
        File file = new File("D:\\tools\\shiro_detect\\src\\main\\resources\\config.yml");
        properties = new Yaml().load(new FileInputStream(file));
        getValueByKey("scan.siteMaxScan");
    }

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
}
