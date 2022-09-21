# shiroDection

## 前言

最近学习了pmiaowu的shiro探测工具，自己敲了一遍代码

主要是学习大佬的思路，然后在其上面做了一点小改动

## 改动

主要有以下两个方面：

- 在基础设置页添加了开启密钥探测选项，可选择只指纹识别不密钥探测
- 将shirokey单独出来做了一个txt，然后在配置页添加了一个textbox用做key添加

![image-20220922001808096](https://user-images.githubusercontent.com/78201553/191558927-72fa208a-5eab-4b54-a9eb-fa80cacb982e.png)

关闭

![image-20220922001916605](https://user-images.githubusercontent.com/78201553/191558942-69ddcde2-e210-4dd6-8f53-ba6042dc4325.png)

开启

![image](https://user-images.githubusercontent.com/78201553/191561562-61d701d8-90f8-4102-828d-ff4ac675b7f3.png)

添加key

![image-20220922001034689](https://user-images.githubusercontent.com/78201553/191559035-b739486a-1357-4557-83af-4a4feb6b5a73.png)

![image-20220922001041930](https://user-images.githubusercontent.com/78201553/191559057-094087f9-9dba-4653-8bca-7db3ddbde357.png)

shirokey全部放在了target\BurpShiroPassiveScan\resources\shiroKey.txt

![image-20220922001209400](https://user-images.githubusercontent.com/78201553/191559087-0ecdff86-9422-4f10-9702-afd968767a44.png)

## ToDo

这个插件还没学完，密钥探测那块我是直接用PrincipalCollection看返回结果

pmiaowu密钥探测中用相似度检测判断waf那块后面再研究研究QwQ

pmiaowu真牛！！

