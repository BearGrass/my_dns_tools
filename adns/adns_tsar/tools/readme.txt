画图脚本使用方法

流程：
先用adns_tsar生成分类数据，再用脚本处理数据文件生成png图片即可。

1、画CPU使用率的图
	adns_tsar --cpu > cpu.txt
	./cpu.sh cpu.txt cpu.png
2、内存使用率的图
	adns_tsar --mem > mem.txt
	./mem.sh mem.txt mem.png
3、画load图
	adns_tsar --load > load.txt
	./load.sh load.txt load.png
4、画TCP重传率
	adns_tsar --tcp > retran.txt
	./retran.sh retran.txt retran.png
5、画in和out的包
	adns_tsar --traffic > traffic.txt
	./packets.sh traffic.txt packets.png
6、画in和out的字节数
	adns_tsar --traffic > traffic.txt
	./bytes.sh traffic.txt bytes.png


若遇使用问题请联系叔度（shudu@taobao.com）
