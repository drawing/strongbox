
# TODO

- [x] 介绍文档
- [ ] 文件系统实现
  - [x] 加密文件
  - [x] ~~文件存储结构 lookback~~
  - [x] 文件存储[badger](https://github.com/dgraph-io/badger)
- [ ] 文件权限管控
  - [x] 通过进程获取 id 名字
  - [x] 进程白名单访问
  - [x] 进程黑名单访问
  - [ ] vscode 访问文件时，当获取进程名时会卡死
  - [ ] 权限管控细分（控制读/写，文件/目录）
  - [x] fake返回（无权限进程查看空目录）
- [x] 操作 GUI[fyne](https://github.com/fyne-io/fyne)
  - [x] GUI 操作 & 配置
  - [x] 权限动态配置生效，无需重启进程
  - [x] 拦截进程记录查看
- [ ] 程序健壮性优化
  - [ ] 异常分支
  - [ ] 通过获取进程名优化
  - [ ] 测试用例
- [x] 信号捕捉，停进程 umount 挂载点
- [x] 配置系统 yaml
- [x] 日志
  - [x] 日志系统 (sirupsen/logrus & lumberjack.v2)
  - [x] 日志格式化
  - [x] 日志等级/路径等可配置
