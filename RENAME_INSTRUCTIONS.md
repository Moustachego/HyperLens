# GitHub 仓库重命名指南

## 在 GitHub 上重命名仓库

### 第一步：在 GitHub 网站上重命名

1. 访问你的 GitHub 仓库：`https://github.com/Moustachego/P4lens`
2. 点击仓库页面右上角的 **Settings**（设置）
3. 在 **General** 设置页面的顶部找到 **Repository name**（仓库名称）
4. 将 `P4lens` 改为 `HyperLens`
5. 点击 **Rename** 按钮
6. GitHub 会自动设置从旧名称到新名称的重定向

### 第二步：更新本地仓库的远程 URL

在你的本地机器上执行以下命令：

```bash
cd /home/long/Desktop/P4lens

# 查看当前远程 URL
git remote -v

# 更新远程 URL（方法1：自动更新）
git remote set-url origin https://github.com/Moustachego/HyperLens.git

# 或者使用 SSH（如果你使用 SSH）
git remote set-url origin git@github.com:Moustachego/HyperLens.git

# 验证更新
git remote -v
```

### 第三步：重命名本地文件夹（可选）

```bash
cd /home/long/Desktop
mv P4lens HyperLens
cd HyperLens

# 提交所有更改
git add .
git commit -m "Rename project from P4lens to HyperLens

- Renamed main source file to HyperLens.cpp
- Updated all references to HyperLens
- Moved output files to src/output/ directory
- Updated build scripts and documentation"

# 推送到 GitHub
git push origin main
```

### 第四步：更新 README.md 标题

GitHub 重命名后，你可能需要更新 README.md 中的任何硬编码的仓库链接：

```bash
# 在 Readme.md 中将所有 P4lens 改为 HyperLens
# 已经完成，无需手动操作
```

## 注意事项

1. **GitHub 会自动重定向**：即使别人使用旧的 `P4lens` URL，也会自动重定向到 `HyperLens`
2. **克隆地址会改变**：新的克隆地址是 `https://github.com/Moustachego/HyperLens.git`
3. **现有的克隆无需更新**：GitHub 的重定向功能会让现有的本地仓库继续工作，但建议更新 remote URL
4. **更新 CI/CD**：如果你有 CI/CD 配置，可能需要更新其中的仓库引用

## 验证重命名成功

```bash
# 1. 检查远程 URL
git remote -v
# 应该显示：
# origin  https://github.com/Moustachego/HyperLens.git (fetch)
# origin  https://github.com/Moustachego/HyperLens.git (push)

# 2. 测试 push
git push origin main

# 3. 访问新的 GitHub 页面
# https://github.com/Moustachego/HyperLens
```

## 已完成的本地更改

✅ 已重命名：
- `src/P4Lens.cpp` → `src/HyperLens.cpp`
- 编译输出：`src/P4Lens` → `src/HyperLens`
- 所有源文件中的 "P4Lens" 引用已更新为 "HyperLens"

✅ 输出目录更改：
- 所有 `.txt` 输出文件现在保存到 `src/output/` 目录
- 包括：SRC_TCAM_Table.txt, SRC_SRAM_Table.txt, DST_TCAM_Table.txt, DST_SRAM_Table.txt, final_ip_table_cidr.txt, meta_merged.txt

✅ 脚本更新：
- `build_and_run.sh` 已更新所有引用
- 编译命令使用新的文件名
- 输出路径检查更新为 `src/output/`

## 快速命令总结

```bash
# 在 GitHub 网站上重命名后，执行：
cd /home/long/Desktop/P4lens
git remote set-url origin https://github.com/Moustachego/HyperLens.git
git add .
git commit -m "Rename project to HyperLens"
git push origin main

# 可选：重命名本地文件夹
cd /home/long/Desktop
mv P4lens HyperLens
```

完成后你的项目就完全从 P4lens 重命名为 HyperLens 了！
