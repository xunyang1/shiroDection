package burp.Bootstrap;

import burp.Application.ShiroCipherKeyExtension.ExtensionInterface.IShiroCipherKeyExtension;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class GlobalPassiveScanVariableReader {
    private ConcurrentHashMap booleanMap;
    private ConcurrentHashMap shiroCipherKeyExtensioMap;

    public GlobalPassiveScanVariableReader() {
        this.booleanMap = new ConcurrentHashMap<String, Boolean>();
        this.shiroCipherKeyExtensioMap = new ConcurrentHashMap<String, IShiroCipherKeyExtension>();
    }

    public void putBooleanData(String key, Boolean b) {
        if (key == null || key.length() <= 0) {
            throw new IllegalArgumentException("key不能为空");
        }

        synchronized (this.getBooleanMap()) {
            this.getBooleanMap().put(key, b);
        }
    }

    public Boolean getBooleanData(String key) {
        return (Boolean) this.booleanMap.get(key);
    }

    public ConcurrentHashMap getBooleanMap() {
        return booleanMap;
    }

    public Map<String, IShiroCipherKeyExtension> getShiroCipherKeyExtensioMap() {
        return this.shiroCipherKeyExtensioMap;
    }

    public IShiroCipherKeyExtension getShiroCipherKeyExtensionData(String key) {
        return this.getShiroCipherKeyExtensioMap().get(key);
    }

    public void putShiroCipherKeyExtensionData(String key, IShiroCipherKeyExtension b) {
        if (key == null || key.length() <= 0) {
            throw new IllegalArgumentException("key不能为空");
        }

        synchronized (this.getShiroCipherKeyExtensioMap()) {
            this.getShiroCipherKeyExtensioMap().put(key, b);
        }
    }
}
