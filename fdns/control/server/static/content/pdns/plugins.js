/**
 * Created with PyCharm.
 * User: zhaolin.huang
 * Date: 14-2-11
 * Time: 下午2:54
 * To change this template use File | Settings | File Templates.
 */
pdns.plugin = {};
//django 插件
pdns.plugin.django_csrf = (function () {
    Ext.onReady(function () {
        function getCookie(name) {
            var cookieValue = null;
            if (document.cookie && document.cookie != '') {
                var cookies = document.cookie.split(';');
                for (var i = 0; i < cookies.length; i++) {
                    var cookie = Ext.util.Format.trim(cookies[i]);
                    // Does this cookie string begin with the name we want?
                    if (cookie.substring(0, name.length + 1) == (name + '=')) {
                        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                        break;
                    }
                }
            }
            return cookieValue;
        }

        Ext.Ajax.on('beforerequest', function (conn, options) {
            if (!(/^http:.*/.test(options.url) || /^https:.*/.test(options.url))) {
                options.headers = options.headers || {};
                options.headers["X-CSRFToken"] = getCookie('csrftoken');
            }
        }, this);
    });
//    console.log("extjs csrf plugin reload success!");
    return "loaded";
})();
/**
 * 在store中搜索需要的数据
 * @type {*}
 */
pdns.plugin.filter_data_from_store = function (store, params) {
    var store_data = store.data.items;
    var filter_result = [];
    for (var i = 0; i < store_data.length; i++) {
        var data = store_data[i].data;
        for (p in params) {
            if (p in data && data[p] == params[p]) {
                data["store_index"] = i;
                filter_result.push(data);
            }
        }
    }
    return filter_result.length == 1 ? filter_result[0] : filter_result;
};
/**
 * 修改alert
 * @type {Function}
 */
alert = pdns.plugin.alert = function (message, title, fn) {
    Ext.Msg.alert(title || "PDNS", message, fn || function () {
    });
};
/**
 *  ext comfirm
 * @param message
 * @param fn
 * @param title
 */
pdns.comfirm = function (message, fn, title) {
    Ext.MessageBox.confirm(title || "PDNS", message, function (btn) {
        if (btn == "yes") {
            fn();
        }
    });
};
/**
 *
 * @param cmp
 */
pdns.plugin.mask = function (cmp) {
    var do_mask_cmp = (cmp && cmp.getEl()) || Ext.getBody();
    do_mask_cmp.mask();
    pdns.masked_cmp = do_mask_cmp;
};
/**
 *unmask
 * @param cmp
 */
pdns.plugin.unmask = function (cmp) {
    var do_mask_cmp = (cmp && cmp.getEl()) || (pdns.masked_cmp && pdns.masked_cmp) || Ext.getBody();
    do_mask_cmp.unmask();
};
pdns.is_number = function (str) {
    if (typeof str == "string") {
        return Boolean(str.match(/^\d+$/))
    } else {
        throw {"message": "is_number paramter string only support"}
    }

};
/**
 *is ip check
 * @param str
 * @returns {*}
 */
pdns.plugin.is_ip = function (str) {
    var exp_ipv4=/^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$/;
    return Boolean(str.match(exp_ipv4))
};
/**
 *
 * @param response
 * @returns {boolean}
 */
pdns.plugin.response_exception = function (response) {
    console.log(response);
    var status = response.status;
    switch (status) {
        case 403:
            alert("没有可操作权限！");
            return false;
        //为了支持集团恶心的400代号
        case 400:
            var resopnse_info = JSON.parse(response.responseText);
            if(resopnse_info["resultCode"] && resopnse_info["message"]){
                alert(resopnse_info["resultCode"] + ":" + resopnse_info["message"]);
            }else{
                alert(response.statusText + ":" + response.responseText);
            }
    }
    return true;
};

pdns.is_hidden_group = function(portal_version){
    return portal_version != 'group';
};

pdns.switch_on = function(switch_on_or_off){
    return switch_on_or_off == 'on';
};

get_store_list = function(store_number){
    var store_list = [];
    for(var i=0;i <store_number;i++){
        var store_example = Ext.create('Ext.data.Store', {
          model : 'StockData',
          data: []
        });
        store_list.push(store_example);
    }
    return store_list;
};


get_series_name_list = function(name_list){
    var series_name_list = [];
    for(var i=0; i<name_list.length;i++){
        var series_name_dic ={
            name : name_list[i],
            xField : 'time',
            yField : 'count'
        };
        series_name_list.push(series_name_dic);
    }
    return series_name_list;
};



time_data_validate = function(start_time, end_time){
    if(start_time != null || end_time != null){
        if(start_time == null){
            alert("请输入起始时间！");
            die;
        }
        if(end_time == null){
            alert("请输入终止时间！");
            die;
        }
        if(start_time > end_time){
            alert("起始时间必须小于终止时间！");
            die;
        }
        start_time = Ext.Date.format(start_time, 'Y-m-d H:i:s');
        end_time = Ext.Date.format(end_time, 'Y-m-d H:i:s');
    }
    return {stime: start_time, etime: end_time}
};
