
QIU Memory Manager 1.0 for Delphi
简称：QMM

描述:
	一个简单的内存管理器for Delphi/XE

主页:
  https://code.google.com/p/qiumm/
  by qiusonglin (qiusonglin.hex@gmail.com)

如何应用到工程:
 - 如同其它MM，将它放置于dpr最上面即可使用

其它注意事项:
 - 注意：QMM仅在D7及D2010测试通过，其它Delphi版本未经测试
 - 请谨慎使用，未经专业测试软件测试
 - 支持多线程，为每线程分配一线程管理器，所以，它是并行分配内存的。
 - 当前版本不支持DLL与APP之间的共享MM（FastMM/scaleMM都支持，N个版本后再考虑）
 - 

技术支持:
  如在使用QMM遇到问题，欢迎来信，如果有BUG或更好的建议更是欢迎:)

License:
  Released under Mozilla Public License 1.1

  If you find QMM useful or you would like to support further development,
  a donation would be much appreciated.
  My PayPal account is: qiusonglin.hex@gmail.com

------------------------------------------------------------------------------

QMM文档包含两个文件:
----------------------
QMM.pas - 用于替换D自带的MM，用于加速你的内存管理
QMM.inc - 配置文件

QMM配置中的可选项(QMM.Inc):
--------------------------------
fastcode - 是否使用fastcode代码, 用于代替系统函数：fillchar and move.
					 该系统函数未像其它MM样，集成到QMM中，进行优化，直接使用fastcode
tls_mode - 使用API: tls相关函数进行处理线程局部变量或用关键字：threadvar

debug release  - 它与应用工程相同

注意：当系统变量System.ReportMemoryLeaksOnShutdown=true，并且为DEBUG模式，
			如果发生内存泄露，QMM将会生成一个文件：memory.leak.txt进行报告该问题

好了，其它问题，有需要请邮给我，但时间精力有限，可能未能及时回复，请见谅:)
------------------------------------------------------------------------------
2013.11.18 by qiusonglin 


		  
		  


