---
title: 配置VSCode编写C/C++教程
date: 2020-09-09T16:05:00+01:00
lastmod: 2020-09-09T16:05:00+01:00
author: Ch4rc0al
# authorlink: https://author.site
cover: /post/VSCode_cover.jpg
categories:
  - VSCode
tags:
  - VSCode	
  - IDE
  - C/C++
  - 教程 
# showcase: true
---


## 简介

Visual Studio Code (简称 VS Code / VSC) 是一款免费**开源**的现代化轻量级代码编辑器，**使用Web技术Electron搭建**，支持几乎所有主流的开发语言的语法高亮、智能代码补全、自定义热键、括号匹配、代码片段、代码对比 Diff、GIT 等特性，**支持插件扩展**。软件跨平台支持 Windows、Mac 以及 Linux。

接触这款编辑器之后的感受正如VSCode官网所述：VSCode Redefined Code Editing.这款编辑器带来的强大的功能是Dev-C++等古董编辑器望尘莫及的。

本文将介绍如何在**Windows**环境下快速配置VSCode编写**C/C++**程序。

<!--more-->

---

## 目录

 1. [安装VScode](#安装vscode)

 2. [配置环境变量](#配置环境变量)

 3. [安装必要的插件](#安装必要的插件)

 4. [创建工作区文件夹并测试代码](#创建工作区文件夹并测试代码)

 5. [进一步的美化和扩展](#进一步的美化和扩展)

---

## 安装VSCode

在[VSCode官网](https://code.visualstudio.com/)下载最新版本的`Stable Build`（稳定版）并安装，可以选择将VSC注册到path或加入右键菜单，方便打开文件。

在终端可以使用`code`命令启动VSC。

---

## 配置环境变量

Windows系统中没有GCC环境，我们需要下载`MinGW-w64`（兼容64位&32位）来配置。

[MinGW-w64 for windows直达](https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/8.1.0/threads-win32/seh/x86_64-8.1.0-release-win32-seh-rt_v6-rev0.7z/download)

下载好后是一个压缩文件包，我们推荐将其中的文件解压到`C:\MinGW-w64\`文件夹下。

打不开下载地址、下载速度太慢或总是失败解决方法
1. 使用**科学上网**
2. [百度云分享链接](https://pan.baidu.com/s/1Otq4gYcJ5KgRbW11LkZafw)  【tmnu】

正确解压后的`MinGW-w64`文件夹样貌如下图

![QQ截图20190403150943.png](https://i.loli.net/2019/04/03/5ca45c99edaf3.png)

接下来就是配置环境变量了，我们在桌面右键`我的电脑（此电脑）`-`属性`-`高级系统设置`-`环境变量`，在`系统变量`下找到`Path`，点击`编辑`-`新建`，然后将`C:\MinGW-w64\bin\`填入，然后点击`确定`保存

![QQ截图20190403152353.png](https://i.loli.net/2019/04/03/5ca45fbdb55db.png)

测试是否成功👇

`Win+R`键打开`运行`输入`cmd`按回车，在弹出的`cmd`窗口中输入`gcc`按回车，如果出现下图情形便说明配置成功，否则重新检查。

![QQ截图20190403152655.png](https://i.loli.net/2019/04/03/5ca460fc5265b.png)

---

## 安装必要的插件

打开VSCode，在左边栏里点击这个图标

![QQ截图20190403172946.png](https://i.loli.net/2019/04/03/5ca47d21690d4.png)

在搜索框中搜索以下

必需插件👇

- `C/C++` 认准 `Microsoft`
- `Chinese (Simplified) Language Pack for Visual Studio Code` 简体中文语言包，应该会自动提示安装
- `Code Runner` 可自定义编译命令的插件，支持很多语言，很方便
- `C/C++ Snippets` 重用代码块,提高代码效率

推荐插件见[进一步的美化和扩展](#进一步的美化和扩展)

下载好插件后，我们需要点`重新载入`来完成对插件的操作。

---

## 创建工作区文件夹并测试代码

接下来我们将创建一个`工作区文件夹`并进行一系列设置

我们在`E盘`下创建一个叫做`VSCODE-C`的文件夹当作我们的~~工作~~刷题文件夹，然后打开一个新的空白VSC窗口，在`欢迎使用`界面的`启动`下找到`添加工作区文件夹`，点击后选中我们刚刚创建的`VSCODE-C`

![QQ截图20190405201121.png](https://i.loli.net/2019/04/05/5ca74602b4fc2.png)

点击左上角`文件`-`将工作区另存为`-选择文件夹`VSCODE-C`-文件名随意（最好也是`VSCODE-C`）-`保存`

这样我们就创建了`VSCODE-C.code-workspace`文件，它是VSC的工作区文件，包含了这个工作区的设置内容。

我们开始设置这个工作区，左上角`文件`-`首选项`-`设置`，新弹出的窗口中有`用户设置`、`工作区设置`、`XXX文件夹设置`，它们的优先程度是后者优于前者，我们点击`工作区设置`，在下方的`常用设置`中可以选择是否开启`自动保存`等方便的功能，大多有中文翻译，英文部分也可以借助翻译搞定。

VSC可设置的地方很多，万幸上面提供了搜索功能，我们在搜索栏中输入关键词找到相关设置

需要设置的项有很多，这里不再赘述，有兴趣的可以在`设置`中细细翻阅，也可以直接使用配置好的`.code-workspace`文件，下面是我配好的设置（附注释）可以按照个人需求修改👇

```json
{
	"folders": [
		{
			"path": "."
		}
	],
	"settings": {
		"files.autoSave": "afterDelay",
		"C_Cpp.default.intelliSenseMode": "gcc-x64",
		"git.enabled": false,
		"files.defaultLanguage": "cpp", // ctrl+N新建文件后默认的语言
		"code-runner.runInTerminal": true, // 设置成false会在“输出”中输出，无法交互
		"code-runner.executorMap": {
			"c": "cd $dir && gcc $fileName -o $fileNameWithoutExt.exe -Wall -g -Og -static-libgcc  -std=c11 && $dir$fileNameWithoutExt",
			"cpp": "cd $dir && g++ $fileName -o $fileNameWithoutExt.exe -Wall -g -Og -static-libgcc -std=c++17 && $dir$fileNameWithoutExt"
		}, // 设置code runner的命令行
		"code-runner.saveFileBeforeRun": true, // run code前保存
		"code-runner.preserveFocus": false, // 若为false，run code后光标会聚焦到终端上。如果需要频繁输入数据可设为false
		"code-runner.clearPreviousOutput": false, // 每次run code前清空属于code runner的终端消息
		"C_Cpp.clang_format_sortIncludes": false, // 格式化时调整include的顺序（按字母排序）
		"C_Cpp.intelliSenseEngine": "Default", // 可以为Default或Tag Parser，后者较老，功能较简单。具体差别参考cpptools插件文档
		"editor.formatOnType": true, // 输入时就进行格式化，默认触发字符较少，分号可以触发
		"editor.snippetSuggestions": "top", // snippets代码优先显示补全
		"terminal.integrated.shell.windows": "C:\\Windows\\system32\\cmd.exe"  //运行终端使用cmd
	}
}
```

保存设置后，我们就可以写一个程序来测试了！

随便写点什么`Hello world`之类的程序，右上角找到一个~~播放键~~▶，点击！

我们看到下面的终端那里，`Code Runner`插件运行了我们已经设置好的编译运行命令，大功告成！

> 有的人的终端默认是PowerShell，解决方法是将上面配置中的`terminal.integrated.shell.windows`项复制并添加到你的工作区设置中，或者在`设置`中搜索`terminal.integrated.shell.windows`，将内容改为`C:\Windows\system32\cmd.exe`

---

## 进一步的美化和扩展

VSC作为一款高度定制的IDE，其扩展插件&主题自然不能少，这里介绍一些推荐的插件

推荐插件👇


- `Include Autocomplete` 头文件补全
- `Bracket Pair Colorizer 2` 彩虹花括号
- `vscode-luogu` 洛谷官方插件，可以看题、提交等，具体见[介绍](https://marketplace.visualstudio.com/items?itemName=himself6565.vscode-luogu)
- `One Dark Pro` 使用人气最高的主题
- `Winter is Coming Theme` 禀冬将至！个人喜欢的主题
- `vscode-icons` VSC文件图标
- `Settings Sync` 用Github将配置存起来，一键上传，一键使用
- `vscode-fileheader` 顶部注释模板，可定义作者、时间等信息，并会自动更新最后修改时间

在`扩展`里搜索`theme`即可看到各种各样的主题，VSC也会根据你最近打开的文件推荐一些可能用到的插件。

快速配置教程到这里就结束了，本文将长期保持更新，如果链接或内容过时请及时联系。