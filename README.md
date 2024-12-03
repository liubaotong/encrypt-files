# 文件加密/解密程序

这是一个简单的文件加密和解密程序，支持对单个文件或整个目录进行加密和解密操作。

## 功能特点

- 支持单个文件的加密和解密
- 支持整个目录（包括子目录）的加密和解密
- 简单的异或加密算法
- 命令行界面操作
- 实时进度显示
- SHA-256文件完整性验证

## 编译方法

### 使用MSVC编译（Visual Studio）

1. 安装依赖
   - 安装Visual Studio（推荐使用Visual Studio 2019或更新版本）
   - 安装OpenSSL开发库
     - 访问 https://slproweb.com/products/Win32OpenSSL.html
     - 下载并安装 Win64 OpenSSL v3.0或更新版本
     - 安装时选择"复制OpenSSL DLL到Windows系统目录"选项

2. 创建项目
   - 打开Visual Studio
   - 创建新的空C++项目
   - 将main.c添加到项目中

3. 配置项目设置
   - 右键项目 -> 属性
   - 配置属性 -> C/C++ -> 常规：
     - 将"SDL检查"设置为"否"
     - 将"警告等级"设置为"级别3(/W3)"
   - 配置属性 -> C/C++ -> 预处理器：
     - 添加预处理器定义：_CRT_SECURE_NO_WARNINGS
   - 配置属性 -> VC++目录：
     - 包含目录：添加OpenSSL include目录（通常是 C:\\Program Files\\OpenSSL-Win64\\include）
     - 库目录：添加OpenSSL lib目录（通常是 C:\\Program Files\\OpenSSL-Win64\\lib）
   - 配置属性 -> 链接器 -> 输入：
     - 添加附加依赖项：libssl.lib;libcrypto.lib;

4. 编译
   - 选择Release x64配置
   - 构建 -> 生成解决方案

### 使用GCC编译（MinGW）

使用gcc编译器编译（需要OpenSSL库）：

```bash
gcc -o crypto main.c -lssl -lcrypto
```

## 使用方法

1. 加密文件或目录：
```bash
crypto -e <文件或目录路径>
```

2. 解密文件或目录：
```bash
crypto -d <文件或目录路径>
```

## 功能说明

### 进度显示
程序会实时显示处理进度，包括：
- 进度条
- 完成百分比
- 已处理/总文件大小

### 完整性验证
程序使用SHA-256算法进行文件完整性验证：
- 显示原始文件的哈希值
- 显示处理后文件的哈希值
- 解密时自动验证文件完整性
- 如果解密后的文件与原始文件不匹配，会显示警告

## 注意事项

- 请确保对重要文件进行备份后再进行加密操作
- 程序使用固定的加密密钥，实际应用中建议使用更安全的加密算法和密钥管理
- 加密和解密操作会直接修改原文件
- 完整性验证可以确保文件在加密/解密过程中没有被损坏

## 示例

加密单个文件：
```bash
crypto -e test.txt
```

加密整个目录：
```bash
crypto -e ./mydocuments
```

解密已加密的文件：
```bash
crypto -d test.txt
```

## 示例输出

加密文件：
```
原始文件哈希值: 7a8b...
test.txt: [====================] 100.0% (1.50/1.50 MB)
test.txt 文件加密成功 (总大小: 1.50 MB)
处理后文件哈希值: 9c4d...
```

解密文件：
```
原始文件哈希值: 9c4d...
test.txt: [====================] 100.0% (1.50/1.50 MB)
test.txt 文件解密成功 (总大小: 1.50 MB)
处理后文件哈希值: 7a8b...
文件完整性验证: 成功 ✓
