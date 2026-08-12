# Android混淆技巧与反混淆-小波

来源: 03-干货系列\移动安全\Android混淆技巧与反混淆-小波.pdf

dac519c3b5927f2762a2fa6a94b630f44ad9d11f 
Android 
混淆技巧与反混淆 

# 
Image from: http://www.usmile.at/sites/default/files/publications/201306_obf_report_0.pdf 
小波 
Bob Pan 
混淆 
反混淆 
dex2jar 
加固 
脱壳 
pxb1988@gmail.com 
About Me 

# 
不冲突, 可联⽤用! 
混淆VS加固 
混淆 
•  将代码变得难以阅读 
•  配置复杂 
   需要开发配合 
加固 
•  隐藏代码 
•  对抗自动化工具 
•  反调试/反篡改/反注入 
•  一键搞定 
    不需要开发配合 

# 
Ref: http://www.saikoa.com/comparison-proguard-and-dexguard 
工具 
•  ProGuard 
•  DexGuard 

# 
缺点:  
λ 接⼝口相关的名字⽆无法替换 
λ 反射很难⾃自动识别 
 
优点:  
λ 代码可读性差 
λ 减少文件大小 
 
名字替换 
•  替换类名 
•  替换函数名 
•  替换成员名 
•  替换所有引用 

# 
•  超长名字 
    oooooooooooooo...  
•  找茬 
    Oo0o0OO00oooOOo0oo 
    ijijijjiiiJiIIjii 
•  __$$_$$$$__$$_ 
•  java语法关键字 
    int int = 5; 
•  Unicode 
•   ȷava \u0237 
•  CJK字符  
•  难以阅读字符 
•  盲文点字模型 
    2800-28FF  
名字替换:奇葩的名字 

# 
-dontshrink 
-dontoptimize 
-dontusemixedcaseclassnames 
-keepattributes *Annotation* 
 
# ⼏几⼤大组件 
-keep public class * extends Activity/Application/... 
... #其他keep, 这⾥里略去 
-dontwarn ** 
-printmapping mapping0.txt 
 
-injars obad-dex2jar.jar 
-outjars aaa.jar 
-libraryjars android.jar 
名字替换:如何对付奇葩 ? 
•  相对来说'abc'是比较好阅读的 
•  Proguard 
  再混淆一次! 

# 
处理前 
处理后 
名字替换:结果比较 

# 名字替换:如何对付abc ? 
•  没办法自动化,
只能靠阅读代码 
•  高富帅 
    JEB 
 
•  普通大众 
    Proguard 

# 
λ 1. ⽣生成默认的mapping文件 
-dontshrink 
-dontoptimize 
-injars aaa.jar 
-libraryjars android.jar 
-keep class * 
-printmapping mapping1.txt 
com.android.system.admin.x -> com.android.system.admin.x: 
    java.lang.String a -> a 
    java.lang.String d -> d 
    int e -> e 
    ... 
Proguard配置 
Mapping文件 
名字替换: Proguard重命名 

# 
λ 2. 修改mapping文件, 重新运行Proguard 
-dontshrink 
-dontoptimize 
-injars aaa.jar 
-outjars bbb.jar 
-libraryjars android.jar 
-applymapping mapping1.txt 
com.android.system.admin.x -> ...ObadSQLiteOpenHelper: 
    android.database.sqlite.SQLiteDatabase f -> database 
    byte[] g -> encoded_data_array 
    java.lang.String a(int,int,int) -> decrypt 
Proguard配置 
Mapping文件 
名字替换: Proguard重命名 

# Proguard重命名结果 

# 
再混淆一次 
⾃自动化重命名 
a → Clz_a 
b → fld_b 
c → mtd_c 
d → Clz_d_List 
⾃自动化分析 
Source 
Enum 
ACC_BRIDGE 
Getter/setter 
识别开源SDK 
⾃自动反编译 
⼿手⼯工调整 
⼿手⼯工分析代码 
+ 
源码在⼿手 
日志 
toString 
反混淆大项目(名字恢复) 

# 
•  将字符串在运行时恢复 
•  DexGuard 
•  String a(int, int, int) 
•  Other 
•  String a(String) 
优点: 
λ 静态看不到字符串 
缺点: 
λ 内存消耗增加 
λ 性能降低 
Class.forName(a(130, 1, -10)) 
.getMethod(a(53, 19, -21), 
 Class.forName(a(79, 1, -11))) 
.invoke(j, instance); 
字符串加密 

# 
getstatic System.out 
LDC “hello world!” 
invokevirtual println(String) 
getstatic System.out 
sipush 130  
sipush 1  
sipush -10  
invokestatic a(int,int,int) 
invokevirtual println(String) 
System.out.println(“hello world!”); 
字符串加密:简单实现 
•  Java bytecode 使用LDC指令加载字符串 
•  替换对应的LDC指令即可实现加密 

# 
λ 使用'==' ⽐比较字符串 
void fa(){ 
  fb(“1.0”); 
} 
void fb(String version) { 
  if(version == “1.0”){ 
    print(“yes!”); 
  } 
} 
void fa(){ 
  fb(new String(...)); 
} 
void fb(String version) { 
  if(version == new String(...)){ 
    print(“yes!”); 
  } 
} 
条件成立, 打印yes 
条件不成立, 什么都没有 
λ 解决办法: 使用'equals' ⽐比较字符串 
字符串加密:带来的问题 

# 
private static String decrypt(int n, int n2, int n3) { 
    … 
} 
 
String a = decrypt(-20, 842, -576); 
解决办法:  
找到对应的函数和参数, 反射调⽤用, 将结果写回. 
字符串加密: 如何应对? 
•  静态函数 
•  返回值是String 
•  解密函数没有对外引用 
•  参数是固定值 

# 
解密前 
解密后 
注:t.q(...)也是解密函数 
字符串解密结果 

# 反射替换 
•  将函数替换为等价的反射API调用 
String c = "abc".substring(2,3); 
String c = (String)Class.forName("java.lang.String") 
        .getMethod("substring", int.class, int.class) 
        .invoke("abc", 2, 3) 
优点: 
λ 与字符加密串结合效果更佳 
缺点: 
λ 代码⼤大⼩小增加 
λ 性能降低 

# 
Local 
Stack 
Opcode 
ldc "abc" 
“abc” 
sipush 2 
“abc”, 2 
sipush 3 
“abc”, 2, 3 
invokevirtual substring(II) 
String c =  
    "abc".substring(2,3); 
1. 将Stack的数据保存到Local 
2. 构建Class对象 
3. 构建Method对象 
4. 重新加载Local中的值到Stack 
5. 调⽤用invoke函数 
思路: 
反射替换: 简单实现 

# 
Local 
Stack 
Opcode 
“abc”, 2, 3 
astore 1, istore 2, istore 3 
“abc”, 2, 3 
ldc “java.lang.String” 
invokestatic Class.forName 
“abc”, 2, 3 
String.class 
ldc “substring”,  
... #构建参数类型 
invokevirtual Class.getMethod 
“abc”, 2, 3 
substring 
aload 1, iload 2, iload 3, 
“abc”, 2, 3 
substring, “abc”, [2, 3] 
invokevirtual Method.invoke() 
String a=”abc”; int b=2; int c=3; 
String c = (String)Class.forName("java.lang.String") 
        .getMethod("substring", int.class, int.class) 
        .invoke(a, b, c) 
等价于 
反射替换: 简单实现 

# 
•  1. 将所有的Class.forName恢复成class对象 
String c = (String)Class.forName("java.lang.String") 
        .getMethod("substring", int.class, int.class) 
        .invoke("abc", 2, 3) 
String c = (String)String.class 
        .getMethod("substring", int.class, int.class) 
        .invoke("abc", 2, 3) 
反射替换:如何处理? 

# 反射替换:如何处理? 
•  2. 将getMethod恢复成对应对象 
String c = (String)String.class 
        .getMethod("substring", int.class, int.class) 
        .invoke("abc", 2, 3) 
String c = (String) 
        [String.substring(II)] 
        .invoke("abc", 2, 3) 
表示一个Method对象 

# 
•  3. 将invoke函数展开 
String c = (String) 
        [String.substring(II)] 
        .invoke("abc", 2, 3) 
String c = (String) 
        ”abc”.substring(2,3) 
反射替换:如何处理? 

# 
清理前: 
清理后: 
清理反射结果 

# 日志清除 
•  清理android日志输出代码 
•  实现原理 
Ref: http://stackoverflow.com/questions/5553146/disable-logcat-output-completely-in-release-android-app/5553290#5553290 
-assumenosideeffects class android.util.Log { 
    public static *** d(...); 
    public static *** w(...); 
    public static *** v(...); 
    public static *** i(...); 
} 

# 
Ref: http://stackoverflow.com/questions/22713166/removing-log-calls-with-proguard-leaves-behind-stringbuilders 
new StringBuilder("version is: ").append(n); 
Log.d(“tag”, “version is ” + version ); 
原因:  
“version is” + version 会被转换成  
new StringBuilder(“version is ”).append(version).toString(). 
而Proguard只负责删除Log.d的函数调⽤用, 没有删除StringBuilder相关的代码 
清理后: 
源代码: 
日志清除: Proguard缺陷 

# 
Ref: http://www.android-decompiler.com/blog/2013/04/07/dexguards-assets-encryption/ 
优点: 
λ 隐藏资源于⽆无形 
缺点: 
λ 必须调⽤用AssetManager.open() 
λ 性能降低 
•  将apk中asset目录的文件加密, 使用前解密 
Asset加密 

# 
InputStream is = this.getAssets().open(); 
Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding"); 
cipher.init(DECRYPT_MODE, /* key */); 
return new CipherInputStream(is, cipher).available(); 
等价于 
Asset加密: 原理 
•  拦截open函数
返回解密流 

# 
原理:  
AndroidManifest中同时包含ResourceId和namespace/name信息. 
而Android部分使用ResourceId查找对应的xml标签. 
这部分的namespace/name信息是多余的, 可以删除. 
AndroidManifest混淆 
•  namespace和name信息被清除 
 

# AndroidManifest恢复 
•  根据ResourceId恢复namesapce/name 
•  Apktool已经支持读取 
•  axml工具也可以 

# 
混淆项 
恢复 
是否可⾃自动化 
难度 
名字替换 
人工恢复 
X 
999999999 
日志清除 
X 
X 
X 
字符串加密 
静态分析+动态运
⾏行 
可以 
5 
反射替换 
静态分析 
可以 
4 
Assert加密 
可以恢复 
半⾃自动化 
2 
XML混淆 
可以恢复 
现成⼯工具 
1 
小结 

# 混淆建议 
•  减少-keep的数量 
•  SDK 
•  JNI代码 
•  反射 
•  序列化/反序列化 
•  清除其他线索 
•  清除SourceFile 
•  避免日志输出 
•  混用混淆项 
•  写烂代码 
•  加固jaq.taobao.com 

pxb1988@gmail.com 
Q & A 
