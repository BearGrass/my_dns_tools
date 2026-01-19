/**
 * @class Ext.app.Portal
 * @extends Object
 * A sample portal layout application class.
 */

Ext.define('Ext.app.Portal', {

    extend: 'Ext.container.Viewport',
    requires: ['Ext.app.PortalPanel', 'Ext.app.PortalColumn', 'Ext.app.GridPortlet', 'Ext.app.ChartPortlet'],

    getTools: function(){
        return [{
            xtype: 'tool',
            type: 'gear',
            handler: function(e, target, header, tool){
                var portlet = header.ownerCt;
                portlet.setLoading('Loading...');
                Ext.defer(function() {
                    portlet.setLoading(false);
                }, 2000);
            }
        }];
    },

    initComponent: function(){
        var content = '<div class="portlet-content">'+Ext.example.shortBogusMarkup+'</div>';
        var domain_function_list = Ext.example.domainFuctionList;
        Ext.apply(this, {
            id: 'app-viewport',
            layout: {
                type: 'border',
                padding: '0 5 5 5' // pad the layout from the window edges
            },
            items: [{
                id: 'app-header',
                xtype: 'box',
                region: 'north',
                height: 50,
                html: '<span class="title-info-bar">'+title_info_bar+' Portal</span>' +
                      '<span class="user-info-bar">您好，'+current_user_last_name+'</span>'

            },{
                xtype: 'container',
                region: 'center',
                layout: 'border',
                items: [{
                    id: 'app-options',
                    title: '功能导航',
                    iconCls: 'icon-location',
                    region: 'west',
                    animCollapse: true,
                    width: 200,
                    minWidth: 150,
                    maxWidth: 400,
                    split: true,
                    collapsible: true,
                    layout:{
                        type: 'accordion',
                        animate: true
                    },
                    items: [{
                        xtype: 'xtree',
                        title:'服务器管理',
                        border: false,
                        autoScroll: true,
                        iconCls: 'icon-server',
                        url: '/server/server_menu_tree/',
                        listeners:{
                            itemclick: function(self, store_record, html_element, node_index, event){
                                if(store_record.data.leaf){
                                    var mainPanel = Ext.getCmp('mainPanel');
                                    var id = store_record.data.id;
                                    var text = store_record.data.text;
                                    var tabId = 'tab-server-' + id;
                                    var title = '服务器管理-' + text;
                                    var html = genIframeTag((function(id){
                                        switch(id){
                                            case "pdns-server-list":
                                                return "/server/pdns_server_manage";
                                        }
                                        return "";
                                    })(id));
                                    addTab(mainPanel, tabId, title, '', html);
                                }
                            }
                        }
                    },{
                        xtype: 'xtree',
                        title:'线路管理',
                        autoScroll: true,
                        border: false,
                        iconCls: 'connect',
                        url: '/view/view_menu_tree/',
                        listeners:{
                            itemclick: function(self, data){
                                if(data.data.leaf){
                                    var mainPanel = Ext.getCmp('mainPanel');
                                    var id = data.data.id;
                                    var text = data.data.text;
                                    var tabId = 'tab-line-' + id;
                                    var title = '线路管理-' + text;
                                    var html = genIframeTag((function(id){
                                        switch(id){
                                            case "view-list":
                                                return "/view/view_page";
                                        }
                                        return "";
                                    })(id));
                                    addTab(mainPanel, tabId, title, '', html);
                                }
                            }
                        }
                    },{
                        xtype: 'xtree',
                        title:'数据展示',
                        autoScroll: true,
                        border: false,
                        iconCls: 'nav',
                        url: '/data_display/data_menu_tree/',
                        listeners:{
                            itemclick: function(self, data){
                                if(data.data.leaf){
                                    var mainPanel = Ext.getCmp('mainPanel');
                                    var id = data.data.id;
                                    var text = data.data.text;
                                    var tabId = 'tab-data-' + id;
                                    var title = '数据展示-' + text;
                                    var html = genIframeTag((function(id){
                                        switch(id){
                                            case "daily-report-graph":
                                                return "/data_display/daily_report";
                                            case "qps-graph":
                                                return "/data_display/qps_graph_view";
                                            case "request-graph":
                                                return "/data_display/request_graph_view";
                                            case "drop-graph":
                                                return "/data_display/drop_graph_view";
                                            case "prefetch-graph":
                                                return "/data_display/prefetch_graph_view";
                                            case "view-graph":
                                                return "/data_display/view_graph_view";
                                            case "rt-graph":
                                                return "/data_display/rt_graph_view";
                                            case "topn-graph":
                                                return "/data_display/topn_graph_view";
                                            case "view-detail-table":
                                                return "/data_display/view_detail_table_view";
                                            case "test-page":
                                                return "/data_display/test_page_view";
                                        }
                                        return "";
                                    })(id));
                                    addTab(mainPanel, tabId, title, '', html);
                                }
                            }
                        }
                    },{
                        xtype: 'xtree',
                        title:'后台管理',
                        autoScroll: true,
                        border: false,
                        iconCls: 'cog',
                        url: '/global_param/global_param_menu_tree/',
                        listeners:{
                            itemclick: function(self, data){
                                if(data.data.leaf){
                                    var mainPanel = Ext.getCmp('mainPanel');
                                    var id = data.data.id;
                                    var text = data.data.text;
                                    var tabId = 'tab-global-control-' + id;
                                    var title = '后台管理-' + text;
                                    var html = genIframeTag((function(id){
                                        switch(id){
                                            case "api-global-param":
                                                return "/global_param/global_param";
                                        }
                                        return "";
                                    })(id));
                                    addTab(mainPanel, tabId, title, '', html);
                                }
                            }
                        }
                    }]
                },{
                    region: 'center',
                    xtype: 'tabpanel',
                    id: 'mainPanel',
                    items: []
                },{
                    xtype: 'box',
                    id: 'footer',
                    region: 'south',
                    html: '<center>Alibaba Group @2015 建议使用Chrome/Firefox浏览器访问，ADMS版本：'+ADMS_version+'</center>',
                    height: 20
                }]
            }]
        });
        this.callParent(arguments);
    },

    onPortletClose: function(portlet) {
        this.showMsg('"' + portlet.title + '" was removed');
    },

    showMsg: function(msg) {
        var el = Ext.get('app-msg'),
            msgId = Ext.id();

        this.msgId = msgId;
        el.update(msg).show();

        Ext.defer(this.clearMsg, 3000, this, [msgId]);
    },

    clearMsg: function(msgId) {
        if (msgId === this.msgId) {
            Ext.get('app-msg').hide();
        }
    }
});


function iframeLoadComplete(){
	var loadMask = Ext.getCmp('loadMask');
	if(loadMask)
		loadMask.hide();
}


function genIframeTag(src){
	return  '<iframe src="'+src+'" width="100%" height="100%"  border=0 frameborder=0 onload="iframeLoadComplete()"></iframe>';
}

function addTab(mainPanel,tabId,title,subTitle,html) {
	var loadMask = Ext.getCmp('loadMask');
	if(!loadMask){
		loadMask = new Ext.LoadMask(mainPanel, {
			id: 'loadMask',
			msg:'正在加载...'
		});
	}
	loadMask.show();
	var find = Ext.getCmp(tabId);
	if(find){
		mainPanel.remove(find);
	}
    var tab;
    if(subTitle!=''){
	    var tab = mainPanel.add({
	    	id: tabId,
	        title: title,
	        html: html,
	        closable: true,
	        tbar: [{ xtype: 'tbtext',id:tabId+'-tbtext',text: subTitle}]
	    });
	}
	else{
		var tab = mainPanel.add({
	    	id: tabId,
	        title: title,
	        html: html,
	        closable: true
	    });
	}
    activeTabHTML = html;
    mainPanel.setActiveTab(tab);
    tab.update(html);//修复chrome高版本，第一次加载iframe height 100%失效的问题
}