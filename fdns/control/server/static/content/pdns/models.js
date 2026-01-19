/**
 * Created with PyCharm.
 * User: zhaolin.huang
 * Date: 14-2-9
 * Time: 下午11:12
 * To change this template use File | Settings | File Templates.
 */
pdns.models = {};

/**
 *
 * @type {*|Ext.Base}
 */
pdns.models.pdns_server = Ext.define('pdns_server', {extend: 'Ext.data.Model',
    proxy: {
        type: 'ajax',
        reader: 'json'
    },
    fields: [
        {name: 'id', type: 'int'},
        {name: 'ip', type: 'string'},
        {name: 'name', type: 'string', mapping: "host"},
        {name: 'port', type: 'int'},
        {name: 'type', type: 'string'},
        {name: 'status', type: 'string'},
        {name: 'pdns_version', type: 'string'},
        {name: 'agent_version', type: 'string'},
        {name: 'agent_status', type: 'string'},
        {name: 'view_id', type: 'string'},
        {name: 'view_name', type: 'string'}
    ]});

/**
 *
 * @type {*|Ext.Base}
 */
pdns.models.global_param = Ext.define('global_param', {extend: 'Ext.data.Model',
    proxy: {
        type: 'ajax',
        reader: 'json'
    },
    fields: [
        {name: 'id', type: 'int'},
        {name: 'name', type: 'string'},
        {name: 'value', type: 'string'},
        {name: 'ttl', type: 'int'},
        {name: 'comment', type: 'string'},
        {name: 'gmt_created', type: 'date'},
        {name: 'gmt_modified', type: 'date'}
    ]});


/**
 * view model
 * @type {*|Ext.Base}
 */
pdns.models.view = Ext.define('view', {extend: 'Ext.data.Model',
    proxy: {
        type: 'ajax',
        reader: 'json'
    },
    fields: [
        {name: 'id', type: 'int'},
        {name: 'name', type: 'string'},
        {name: 'cn_name', type: 'string'},
        {name: 'isp_simulate', type: 'string'},
        {name: 'fallback_id', type: 'string'},
        {name: 'cdn_ids', type: 'string'}
    ]});


Ext.define('StockData', {
    extend : 'Ext.data.Model',
    fields : [
        {name : 'time', mapping : 0},
        {name : 'count', mapping : 1}
    ]
});


pdns.models.view_detail = Ext.define('view_detail', {
    extend : 'Ext.data.Model',
    fields : [
        {name: 'time', type: 'string'},
        {name : 'view_name', type : 'string'},
        {name : 'backup_view', type : 'string'},
        {name : 'in_req', type : 'int'},
        {name : 'top_in_req', type : 'int'},
        {name : 'top_hit_req', type : 'int'},
        {name : 'backup_in_req', type : 'int'},
        {name : 'backup_out_req', type : 'int'},
        {name : 'hit_req', type : 'int'},
        {name : 'fwd_req', type : 'int'},
        {name : 'fwd_timeout', type : 'int'}
    ]
});