### 构建&编译

安装 rust 环境

根据您的操作系统，参照 https://www.rust-lang.org/tools/install 文档描述进行安装

安装成功后，除了rustc 编译器之外，同时会安装rust相关的工具链，其中cargo最为常用

安装完成后，打开新的终端 输入 cargo -v 查看是否已经成功安装 cargo 命令

### 安装wasm-pack
要构建我们的包，我们需要一个额外工具 wasm-pack。它会帮助我们把我们的代码编译成 WebAssembly 并制造出适用于web环境的wasm包。使用下面的命令可以下载并安装它：

```
cargo install wasm-pack
```

### 编译wasm

wasm-pack安装成功后，执行下面的命令以编译wasm包

```
SECRET=<your-secret> wasm-pack build --target=web --release
```

替换 <your-secret> 为你的签名盐值

第一次构建和编译时间会比较长，需要下载依赖的rust库并编译，请耐心等待

如果速度仍然很慢，建议更换cargo国内源

### 更换 cargo 源

在你的cargo文件夹下新建 config 文件

macos中，文件夹地址在 ~/.cargo

```
cd ~/.cargo
touch config
```

然后编辑config文件，添加如下内容：

```
[source.crates-io]
registry = "https://github.com/rust-lang/crates.io-index"
replace-with = 'ustc'
[source.ustc]
registry = "git://mirrors.ustc.edu.cn/crates.io-index"
```

即可更换为ustc的源

参考资料：

https://developer.mozilla.org/zh-CN/docs/WebAssembly/Rust_to_wasm
https://rustwasm.github.io/wasm-bindgen/examples/without-a-bundler.html