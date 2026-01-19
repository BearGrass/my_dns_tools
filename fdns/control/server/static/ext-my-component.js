/**
 * @class Ext.ux.TreePicker
 * @extends Ext.form.field.Picker
 * 
 * A Picker field that contains a tree panel on its popup, enabling selection of tree nodes.
 */
Ext.define('Ext.ux.TreePicker', {
    extend: 'Ext.form.field.Picker',
    xtype: 'treepicker',

    triggerCls: Ext.baseCSSPrefix + 'form-arrow-trigger',

    config: {
        /**
         * @cfg {Ext.data.TreeStore} store
         * A tree store that the tree picker will be bound to
         */
        store: null,

        /**
         * @cfg {String} displayField
         * The field inside the model that will be used as the node's text.
         * Defaults to the default value of {@link Ext.tree.Panel}'s `displayField` configuration.
         */
        displayField: null,

        /**
         * @cfg {Array} columns
         * An optional array of columns for multi-column trees
         */
        columns: null,

        /**
         * @cfg {Boolean} selectOnTab
         * Whether the Tab key should select the currently highlighted item. Defaults to `true`.
         */
        selectOnTab: true,

        /**
         * @cfg {Number} maxPickerHeight
         * The maximum height of the tree dropdown. Defaults to 300.
         */
        maxPickerHeight: 300,

        /**
         * @cfg {Number} minPickerHeight
         * The minimum height of the tree dropdown. Defaults to 100.
         */
        minPickerHeight: 100
    },
   
    editable: false,

    initComponent: function() {
        var me = this;
        me.callParent(arguments);

        this.addEvents(
            /**
             * @event select
             * Fires when a tree node is selected
             * @param {Ext.ux.TreePicker} picker        This tree picker
             * @param {Ext.data.Model} record           The selected record
             */
            'select'
        );

        me.store.on('load', me.onLoad, me);
    },

    /**
     * Creates and returns the tree panel to be used as this field's picker.
     * @private
     */
    createPicker: function() {
        var me = this,
            picker = Ext.create('Ext.tree.Panel', {
                store: me.store,
                floating: true,
                hidden: true,
                displayField: me.displayField,
                columns: me.columns,
                maxHeight: me.maxTreeHeight,
                shadow: false,
                manageHeight: false,
                listeners: {
                    itemclick: Ext.bind(me.onItemClick, me)
                },
                viewConfig: {
                    listeners: {
                        render: function(view) {
                            view.getEl().on('keypress', me.onPickerKeypress, me);
                        }
                    }
                }
            }),
            view = picker.getView();

        view.on('render', me.setPickerViewStyles, me);

        if (Ext.isIE9 && Ext.isStrict) {
            // In IE9 strict mode, the tree view grows by the height of the horizontal scroll bar when the items are highlighted or unhighlighted.
            // Also when items are collapsed or expanded the height of the view is off. Forcing a repaint fixes the problem.
            view.on('highlightitem', me.repaintPickerView, me);
            view.on('unhighlightitem', me.repaintPickerView, me);
            view.on('afteritemexpand', me.repaintPickerView, me);
            view.on('afteritemcollapse', me.repaintPickerView, me);
        }
        return picker;
    },

    /**
     * Sets min/max height styles on the tree picker's view element after it is rendered.
     * @param {Ext.tree.View} view
     * @private
     */
    setPickerViewStyles: function(view) {
        view.getEl().setStyle({
            'min-height': this.minPickerHeight + 'px',
            'max-height': this.maxPickerHeight + 'px'
        });
    },

    /**
     * repaints the tree view
     */
    repaintPickerView: function() {
        var style = this.picker.getView().getEl().dom.style;

        // can't use Element.repaint because it contains a setTimeout, which results in a flicker effect
        style.display = style.display;
    },

    /**
     * Aligns the picker to the input element
     * @private
     */
    alignPicker: function() {
        var me = this,
            picker;

        if (me.isExpanded) {
            picker = me.getPicker();
            if (me.matchFieldWidth) {
                // Auto the height (it will be constrained by max height)
                picker.setWidth(me.bodyEl.getWidth());
            }
            if (picker.isFloating()) {
                me.doAlign();
            }
        }
    },

    /**
     * Handles a click even on a tree node
     * @private
     * @param {Ext.tree.View} view
     * @param {Ext.data.Model} record
     * @param {HTMLElement} node
     * @param {Number} rowIndex
     * @param {Ext.EventObject} e
     */
    onItemClick: function(view, record, node, rowIndex, e) {
        this.selectItem(record);
    },

    /**
     * Handles a keypress event on the picker element
     * @private
     * @param {Ext.EventObject} e
     * @param {HTMLElement} el
     */
    onPickerKeypress: function(e, el) {
        var key = e.getKey();

        if(key === e.ENTER || (key === e.TAB && this.selectOnTab)) {
            this.selectItem(this.picker.getSelectionModel().getSelection()[0]);
        }
    },

    /**
     * Changes the selection to a given record and closes the picker
     * @private
     * @param {Ext.data.Model} record
     */
    selectItem: function(record) {
        var me = this;
        me.setValue(record.get('id'));
        me.picker.hide();
        me.inputEl.focus();
        me.fireEvent('select', me, record)

    },

    /**
     * Runs when the picker is expanded.  Selects the appropriate tree node based on the value of the input element,
     * and focuses the picker so that keyboard navigation will work.
     * @private
     */
    onExpand: function() {
        var me = this,
            picker = me.picker,
            store = picker.store,
            value = me.value;

        if(value) {
            picker.selectPath(store.getNodeById(value).getPath());
        } else {
            picker.getSelectionModel().select(store.getRootNode());
        }

        Ext.defer(function() {
            picker.getView().focus();
        }, 1);
    },

    /**
     * Sets the specified value into the field
     * @param {Mixed} value
     * @return {Ext.ux.TreePicker} this
     */
    setValue: function(value) {
        var me = this,
            record;

        me.value = value;

        if (me.store.loading) {
            // Called while the Store is loading. Ensure it is processed by the onLoad method.
            return me;
        }
            
        // try to find a record in the store that matches the value
        record = value ? me.store.getNodeById(value) : me.store.getRootNode();

        // set the raw value to the record's display field if a record was found
        me.setRawValue(record ? record.get(this.displayField) : '');

        return me;
    },


    /**
     * Returns the current data value of the field (the idProperty of the record)
     * @return {Number}
     */
    getValue: function() {
        return this.value;
    },

    /**
     * Handles the store's load event.
     * @private
     */
    onLoad: function() {
        var value = this.value;

        if (value) {
            this.setValue(value);
        }
    }

});



Ext.define('Ext.ux.form.SearchField', {
    extend: 'Ext.form.field.Trigger',
    alias: 'widget.searchfield',

    trigger1Cls: Ext.baseCSSPrefix + 'form-clear-trigger',

    trigger2Cls: Ext.baseCSSPrefix + 'form-search-trigger',

    hasSearch : false,
    paramName : 'query',

    initComponent: function() {
        var me = this;

        me.callParent(arguments);
        me.on('specialkey', function(f, e){
            if (e.getKey() == e.ENTER) {
                me.onTrigger2Click();
            }
        });

        // We're going to use filtering
        me.store.remoteFilter = true;

        // Set up the proxy to encode the filter in the simplest way as a name/value pair

        // If the Store has not been *configured* with a filterParam property, then use our filter parameter name
        if (!me.store.proxy.hasOwnProperty('filterParam')) {
            me.store.proxy.filterParam = me.paramName;
        }
        me.store.proxy.encodeFilters = function(filters) {
            return filters[0].value;
        }
    },

    afterRender: function(){
        this.callParent();
        this.triggerCell.item(0).setDisplayed(false);
    },

    onTrigger1Click : function(){
        var me = this;

        if (me.hasSearch) {
            me.setValue('');
            me.store.clearFilter();
            me.hasSearch = false;
            me.triggerCell.item(0).setDisplayed(false);
            me.updateLayout();
        }
    },

    onTrigger2Click : function(){
        var me = this,
            value = me.getValue();

        if (value.length > 0) {
            // Param name is ignored here since we use custom encoding in the proxy.
            // id is used by the Store to replace any previous filter
            me.store.filter({
                id: me.paramName,
                property: me.paramName,
                value: value
            });
            me.hasSearch = true;
            me.triggerCell.item(0).setDisplayed(true);
            me.updateLayout();
        }
    }
});


Ext.define('Ext.adms.TextField', {
    extend: 'Ext.form.TextField',
    xtype: 'xtextfield',
    blankText : '',
    initComponent: function () {
        var me = this;
        
        if(me.blankText == '')
        	me.blankText = me.emptyText = '请输入' + me.fieldLabel;//extend
        else
        	me.emptyText = me.blankText
        	
        me.callParent();
    }
});

Ext.define('Ext.adms.TextField', {
    extend: 'Ext.form.TextField',
    xtype: 'textFieldForTip',
    blankText : '',
    allowBlank: true,
    readOnly: true,
    fieldStyle:'padding: 1px 0;font-weight:bold;padding:0;' +
                    'border-style: solid;font-size: 16px;' +
                    'color: rosybrown;text-shadow: 0 1px 0 #fff;' +
                    'font-family: helvetica, arial, verdana, sans-serif;' +
                    'border: 0;padding: 1px 0px;',
    initComponent: function () {
        var me = this;
        if(me.tipText == '')
        	me.tipText = me.emptyText = '请输入' + me.fieldLabel;//extend
        else
        	me.emptyText = me.tipText
        me.callParent();
    }
});

Ext.define('Ext.adms.TextArea', {
    extend: 'Ext.form.TextArea',
    xtype: 'xtextarea',
    blankText : '',
    initComponent: function () {
        var me = this;
        
        if(me.blankText == '')
        	me.blankText = me.emptyText = '请输入' + me.fieldLabel;//extend
        else
        	me.emptyText = me.blankText
        	
        me.callParent();

    }
    
});
Ext.define('Ext.adms.RadioGroup', {
    extend: 'Ext.form.RadioGroup',
    xtype: 'xradiogroup',
    defaultType: 'radio',
    allowBlank: false,
    layout:'column',
    currentValue: '',
    name: '',
    initComponent: function () {
        var me = this;
        
        me.items = [{
            boxLabel  : '是',
            columnWidth:0.1,
            name      : me.name,
            checked   : me.currentValue == '1',
            inputValue: '1'
        },{
            boxLabel  : '否',
            columnWidth:0.1,
            name      : me.name,
            checked   : me.currentValue == '0',
            inputValue: '0'
        }];

        me.callParent();

    }
    
});
Ext.define('Ext.adms.CheckboxGroup', {
    extend: 'Ext.form.CheckboxGroup',
    xtype: 'xcheckboxgroup',
    layout:'column',
    name: '',
    valueMap: null,
    checkedItems: null,
    initComponent: function () {
        var me = this;
        me.items = []
        for(var k in me.valueMap){
        	me.items.push({boxLabel:me.valueMap[k],padding:5,name: me.name,inputValue:k,checked:me.checkedItems ? in_array(me.checkedItems,k) : false});
        }

        me.callParent();

    }
    
});
Ext.define('Ext.adms.NumberField', {
    extend: 'Ext.form.NumberField',
    xtype: 'xnumberfield',
	minValue: 1,
    initComponent: function () {
        var me = this;
        
        me.blankText = me.emptyText = '请输入' + me.fieldLabel + '（正整数）';//extend

        me.callParent();

    }
    
});

Ext.define('Ext.adms.TreePicker', {
    extend: 'Ext.ux.TreePicker',
    xtype: 'xtreepicker',
    url: '',
    initComponent: function () {
        var me = this;
        
        if(!me.store){
            
	        me.store = Ext.create('Ext.data.TreeStore', {
	            root: {
	                expanded: true
	            },
	            proxy: {
	                type: 'ajax',
	                url: me.url
	            }
	        });
	        
        }
        
        me.blankText = me.emptyText = '请选择' + me.fieldLabel;
        me.callParent();
    }

});

Ext.define('Ext.adms.DateField', {
    extend: 'Ext.form.DateField',
    xtype: 'xdatefield',
    format : 'Y-m-d',
    editable : false,
    initComponent: function () {
        var me = this;
        me.blankText = me.emptyText = '请选择' + me.fieldLabel;
        me.callParent();
    }

});

Ext.define('Ext.adms.ComboBox', {
    extend: 'Ext.form.ComboBox',
    xtype: 'xcombo',
    forceSelection: true,
    url : '',
    currentValue: '',
    editable : false,
    initComponent: function () {
        var me = this;
        me.store = Ext.create('Ext.data.Store', {
    	    autoLoad: true,
    	    fields:[me.valueField,me.displayField],
    	    proxy: {
    	        type: 'ajax',
    	        url: me.url,
    	        reader: {
    	            type: 'json',
                    idProperty: me.valueField,
                    totalProperty: 'total',
                    root: 'result'
    	        }
    	    }
    	});
        me.blankText = me.emptyText = '请选择' + me.fieldLabel;
        me.callParent();
        
        me.value = me.currentValue.toString();

    }
    
});


Ext.define('Ext.adms.FormPanel', {
    extend: 'Ext.form.FormPanel',
    xtype: 'xform',
    hiddenName: '',
    border: false,
	bodyStyle: {
        padding: '10px'
    },
    layout:'form',
    defaults:{
    	labelSeparator: '',
    	labelWidth : 100,
    	allowOnlyWhitespace: false
    },
    url: '',
    successCallback : null,
    failureCallback : null,
    buttonText:'保存',
    initComponent: function () {
        var me = this;
        
        if(!me.buttons){
        	me.buttons = []
        }
        if(me.failureCallback==null){
        	me.failureCallback = function(form, action){
                Ext.MessageBox.alert('提示', action.response.responseText);
            }
        }
        me.buttons.push({
	        text: me.buttonText,
	        formBind: true,
	        disabled: true,
	        handler: function() {
	        	var real_url = me.url;
	        	if(me.hiddenName != ''){
	        		real_url = me.url + '?' + me.hiddenName + '=' + Ext.getCmp(me.hiddenName).getValue();
	        	}
	        	me.getForm().submit({
                    url: real_url,
                    method:'POST',
                    timeout: 1200,
                    waitTitle : '提示',
                    waitMsg: '正在保存...',
                    success: me.successCallback,
                    failure: me.failureCallback
                });
			    
	        }
        });
        
        me.callParent();
        
    }
    
});

Ext.define('Ext.adms.PieChart', {
    extend: 'Ext.chart.Chart',
    xtype: 'xpiechart',
    animate: true,
    url: '',
    shadow: true,
    legend: {
        position: 'right'
    },
    insetPadding: 30,
    labelDisplay: 'rotate',
    theme: 'Base:gradients',
    serieClickCallback : null,
    initComponent: function () {
        var me = this;
        me.store = Ext.create('Ext.data.Store', {
    	    autoLoad: true,
    	    fields: ['name','data'],
    	    proxy: {
    	        type: 'ajax',
    	        url: me.url,
    	        reader: {
    	            type: 'json',
                    idProperty: 'name',
                    totalProperty: 'total',
                    root: 'result'
    	        }
    	    }
    	});
        me.series = [];
        me.series.push({
            type: 'pie',
            field: 'data',
            showInLegend: true,
            tips: {
              trackMouse: true,
              width: 160,
              height: 50,
              renderer: function(storeItem, item) {
                //calculate percentage.
                var total = 0;
                me.store.each(function(rec) {
                    total += rec.get('data');
                });
                this.setTitle(storeItem.get('name') + '<br /> ' + '共: ' + storeItem.get('data') + ',占比:' + Math.round(storeItem.get('data') / total * 100) + '%');
              }
            },
            highlight: {
              segment: {
                margin: 20
              }
            },
            label: {
                field: 'name',
                display: me.labelDisplay,
                contrast: true,
                font: '18px Arial'
            },
            listeners : {  
                itemclick : function(o) {  
                    var rec = me.store.getAt(o.index);  
                    me.serieClickCallback(rec); 
                }  
            }
        });
        
        me.callParent();
    }
});

Ext.define('Ext.adms.TitlePieChart', {
    extend: 'Ext.chart.Chart',
    xtype: 'xtitlepiechart',
    animate: true,
    url: '',
    shadow: true,
    legend: {
        position: 'right'
    },
    insetPadding: 30,
    labelDisplay: 'rotate',
    theme: 'Base:gradients',
    xtitle: null,
    serieClickCallback : null,
    initComponent: function () {
        var me = this;
        me.store = Ext.create('Ext.data.Store', {
    	    autoLoad: true,
    	    fields: ['name','data'],
    	    proxy: {
    	        type: 'ajax',
    	        url: me.url,
    	        reader: {
    	            type: 'json',
                    idProperty: 'name',
                    totalProperty: 'total',
                    root: 'result'
    	        }
    	    }
    	});
        me.series = [];
        me.series.push({
            type: 'pie',
            field: 'data',
            showInLegend: true,
            tips: {
              trackMouse: true,
              width: 160,
              height: 25,
              renderer: function(storeItem, item) {
                //calculate percentage.
                var total = 0;
                me.store.each(function(rec) {
                    total += rec.get('data');
                });
                this.setTitle('共 : ' + storeItem.get('data') + ',占比:' + Math.round(storeItem.get('data') / total * 100) + '%');
              }
            },
            highlight: {
              segment: {
                margin: 20
              }
            },
            label: {
                field: 'name',
                display: me.labelDisplay,
                contrast: true,
                font: '18px Arial'
            },
            listeners : {  
                itemclick : function(o) {  
                	var title = me.xtitle;
                	var rec = me.store.getAt(o.index);
                	me.serieClickCallback(title, rec);
                }  
            }
        });        
        me.callParent();
    }
});

Ext.define('Ext.adms.BarChart', {
    extend: 'Ext.chart.Chart',
    xtype: 'xbarchart',
    animate: true,
    url: '',
    xName: '',
    yName: '',
    initComponent: function () {
        var me = this;
        me.store = Ext.create('Ext.data.Store', {
    	    autoLoad: true,
    	    fields: ['name','data'],
    	    proxy: {
    	        type: 'ajax',
    	        url: me.url,
    	        reader: {
    	            type: 'json',
                    idProperty: 'name',
                    totalProperty: 'total',
                    root: 'result'
    	        }
    	    }
    	});
        me.axes = [];
        me.axes.push({
            type: 'Numeric',
            position: 'bottom',
            fields: ['data'],
            label: {
                renderer: Ext.util.Format.numberRenderer('0,0')
            },
            title: me.yName,
            grid: true,
            minimum: 0
        });
        me.axes.push({
            type: 'Category',
            position: 'left',
            fields: ['name'],
            title: me.xName
        });
        me.series = []
        me.series.push({
            type: 'bar',
            axis: 'bottom',
            highlight: true,
            tips: {
              trackMouse: true,
              width: 140,
              height: 28,
              renderer: function(storeItem, item) {
                this.setTitle(storeItem.get('name') + ': ' + storeItem.get('data') + ' views');
              }
            },
            label: {
              display: 'insideEnd',
                field: 'data',
                renderer: Ext.util.Format.numberRenderer('0'),
                orientation: 'horizontal',
                color: '#333',
                'text-anchor': 'middle'
            },
            xField: 'name',
            yField: 'data'
        });
        
        me.callParent();
    }
});

Ext.define('Ext.adms.ColumnChart', {
    extend: 'Ext.chart.Chart',
    xtype: 'xcolumnchart',
    animate: true,
    theme: 'ColumnTheme',
    url: '',
    xName: '',
    yName: '',
    initComponent: function () {
        var me = this;
        me.store = Ext.create('Ext.data.Store', {
    	    autoLoad: true,
    	    fields: ['name','data'],
    	    proxy: {
    	        type: 'ajax',
    	        url: me.url,
    	        reader: {
    	            type: 'json',
                    idProperty: 'name',
                    totalProperty: 'total',
                    root: 'result'
    	        }
    	    }
    	});
        me.axes = [];
        me.axes.push({
            type: 'Numeric',
            position: 'left',
            fields: ['data'],
            label: {
                renderer: Ext.util.Format.numberRenderer('0.0')
            },
            title: me.yName,
            grid: true,
            minimum: 0
        });
        me.axes.push({
            type: 'Category',
            position: 'bottom',
            fields: ['name'],
            title: me.xName
        });
        me.series = []
        me.series.push({
            type: 'column',
            axis: 'left',
            highlight: true,
            tips: {
              trackMouse: true,
              width: 140,
              height: 25,
              renderer: function(storeItem, item) {
                this.setTitle(storeItem.get('name') + ': ' + storeItem.get('data'));
              }
            },
            label: {
              display: 'insideEnd',
                field: 'data',
                renderer: Ext.util.Format.numberRenderer('0.00'),
                orientation: 'horizontal',
                color: '#333',
                'text-anchor': 'middle'
            },
            xField: 'name',
            yField: 'data',
            listeners : {  
                    itemclick : function(o) {         	
                    	var title = me.xtitle;
                    	var rec = o.value[0];
                        me.serieClickCallback(title, rec); 
                    }  
                }
        });
        
        me.callParent();
    }
});

Ext.define('Ext.adms.MuiltColumnChart', {
    extend: 'Ext.chart.Chart',
    xtype: 'x2columnchart',
    animate: true,
    url: '',
    xName: '',
    yName: '',
    initComponent: function () {
        var me = this;
        me.store = Ext.create('Ext.data.Store', {
    	    autoLoad: true,
    	    fields: ['name','data0','data1','tip'],
    	    proxy: {
    	        type: 'ajax',
    	        url: me.url,
    	        reader: {
    	            type: 'json',
                    idProperty: 'name',
                    totalProperty: 'total',
                    root: 'result'
    	        }
    	    }
    	});
        me.axes = [];
        me.axes.push({
            type: 'Numeric',
            position: 'left',
            fields: ['data0','data1'],
            label: {
                renderer: Ext.util.Format.numberRenderer('0,0')
            },
            title: me.yName,
            grid: true,
            minimum: 0
        });
        me.axes.push({
            type: 'Category',
            position: 'bottom',
            fields: ['name'],
            title: me.xName
        });
        me.series = []
        me.series.push({
            type: 'column',
            stacked: true,
            axis: 'left',
            tips: {
              trackMouse: true,
              width: 140,
              height: 25,
              renderer: function(storeItem, item) {
                this.setTitle(storeItem.get('name') + '(' + storeItem.get('tip') + ')' + ': ' + storeItem.get('data1'));
              }
            },
            label: {
              display: 'insideEnd',
                field: 'data0',
                renderer: Ext.util.Format.numberRenderer('0'),
                orientation: 'horizontal',
                color: '#333',
                'text-anchor': 'middle'
            },
            yPadding: 8,
            xField: 'name',
            yField: ['data0','data1']
        });
        
        me.callParent();
    }
});
Ext.define('Ext.adms.Window', {
    extend: 'Ext.Window',
    xtype: 'xwindow',
    modal: true,
    constrainHeader:true
    
});

Ext.define('Ext.adms.GridPanel', {
    extend: 'Ext.grid.GridPanel',
    xtype: 'xgrid',
    forceFit: true,
    autoHeight:true,
    url: '',
    needPaging:true,
    initComponent: function () {
        var me = this;
        if(!me.plugins){
            me.plugins = [];
            me.plugins.push(Ext.create('Ext.grid.plugin.CellEditing', {
                clicksToEdit: 1
            }));
        }
        if(!me.store){
        	var fields = [];
            Ext.each(me.columns,function(column,i){
            	if(column.columns){
            		Ext.each(column.columns,function(c,j){
            			if(!c.editor){
                    		c.editor = 'displayfield'
                    	}
            		});
            	}
            	else{
            		if(!column.editor){
            			column.editor = 'displayfield'
                	}
            	}
            });
            Ext.each(me.columns,function(column,i){
            	if(column.columns){
            		Ext.each(column.columns,function(c,j){
            			fields.push(c.dataIndex);
            		});
            	}
            	else{
            		fields.push(column.dataIndex);
            	}
            });
            
	        me.store = Ext.create('Ext.data.Store', {
	    	    autoLoad: true,
		        pageSize:15,
	    	    fields: fields,
	    	    proxy: {
	    	        type: 'ajax',
	    	        url: me.url,
	    	        reader: {
	    	            type: 'json',
	                    idProperty: 'id',
	                    totalProperty: 'total',
	                    root: 'result'
	    	        }
	    	    }
	    	});
	        if(me.needPaging){
		        me.bbar = Ext.create('Ext.PagingToolbar', {   
			        store: me.store,   
			        displayInfo: true,
			        displayMsg: '显示 {0} - {1} 条，共计 {2} 条',   
			        emptyMsg: "没有数据"   
		        });
	        }
        }
        me.callParent();
    }

});

Ext.define('Ext.adms.TreePanel', {
    extend: 'Ext.tree.TreePanel',
    xtype: 'xtree',
    rootVisible: false,
    autoScroll: false,
    url: '',
    initComponent: function () {
        var me = this;
        
        if(!me.store){
            
	        me.store = Ext.create('Ext.data.TreeStore', {
	            root: {
	                expanded: true
	            },
	            proxy: {
	                type: 'ajax',
	                url: me.url
	            }
	        });
	        
        }
        me.callParent();
    }

});
Ext.define('Ext.adms.TreeGridPanel', {
    extend: 'Ext.tree.TreePanel',
    xtype: 'xtreegrid',
    rootVisible: false,
    singleExpand: false,
    autoScroll: true,
    overflowY: 'scroll',
    forceFit: true,
    deferRowRender: true,
    url: '',
    initComponent: function () {
        var me = this;
        if(!me.store){
        	var fields = [];
        	Ext.each(me.columns,function(column,i){
            	if(column.columns){
            		Ext.each(column.columns,function(c,j){
            			fields.push(c.dataIndex);
            		});
            	}
            	else{
            		fields.push(column.dataIndex);
            	}
            });
        	Ext.define('Mod', {
    	        extend: 'Ext.data.Model',
    	        fields: fields
    	    });
	        me.store = Ext.create('Ext.data.TreeStore', {
            	model: 'Mod',
                proxy: {
                    type: 'ajax',
                    url: me.url
                },
                folderSort: true
	        });
	        
        }
        me.callParent();
    }

});


Ext.define('Ext.adms.PropertyGrid', {
    extend: 'Ext.grid.PropertyGrid',
    xtype: 'xpropertygrid',
    padding:10,
	hideHeaders :true,
	width: 400,
	sortableColumns:false,
	listeners: {
		beforeedit : function(e){
			e.cancel = true;  
	    	return false;
		}
	}

});

Ext.define('Ext.adms.CardPanel', {
    extend: 'Ext.Panel',
    xtype: 'xcard',
    border: false,
    layout: {
        type: 'card'
    },
    activeItem: 0,
    bbar: [{            
        id: 'move-prev',            
        text: '上一步',
        iconCls: 'icon-arrow-left',
        handler: function(btn) {
            var layout = btn.up("panel").getLayout();
            layout["prev"]();     
            Ext.getCmp('move-prev').setDisabled(!layout.getPrev());     
            Ext.getCmp('move-next').setDisabled(!layout.getNext());
        },
        disabled: true
    },
    {
        id: 'move-next',            
        text: '下一步',
        iconCls: 'icon-arrow-right',
        handler: function(btn) {
            var layout = btn.up("panel").getLayout();
            layout["next"]();     
            Ext.getCmp('move-prev').setDisabled(!layout.getPrev());     
            Ext.getCmp('move-next').setDisabled(!layout.getNext());
        }
    }]

});



/**
 * 合并单元格
 * @param {} grid  要合并单元格的grid对象
 * @param {} cols  要合并哪几列 [1,2,4]
 */
var mergeCells = function(grid,cols){
	var tbodyId = document.getElementById(grid.getId()+"-body").firstChild.id+'-body';
	var arrayTr = document.getElementById(tbodyId).getElementsByTagName('tr');	
	var trCount = arrayTr.length;
	var arrayTd;
	var td;
	var merge = function(rowspanObj,removeObjs){ //定义合并函数
		if(rowspanObj.rowspan != 1){
			arrayTd =arrayTr[rowspanObj.tr].getElementsByTagName("td"); //合并行
			td=arrayTd[rowspanObj.td-1];
			td.rowSpan=rowspanObj.rowspan;
			td.vAlign="middle";				
			Ext.each(removeObjs,function(obj){ //隐身被合并的单元格
				arrayTd =arrayTr[obj.tr].getElementsByTagName("td");
				arrayTd[obj.td-1].style.display='none';							
			});
		}	
	};	
	var rowspanObj = {}; //要进行跨列操作的td对象{tr:1,td:2,rowspan:5}	
	var removeObjs = []; //要进行删除的td对象[{tr:2,td:2},{tr:3,td:2}]
	var col;
	Ext.each(cols,function(colIndex){ //逐列去操作tr
		var rowspan = 1;
		var divHtml = null;//单元格内的数值		
		for(var i=0;i<trCount;i++){
			arrayTd = arrayTr[i].getElementsByTagName("td");
			var cold=0;
			/*Ext.each(arrayTd,function(Td){ //获取RowNumber列和check列
				if(Td.getAttribute("class").indexOf("x-grid-cell-inner-row-expander") != -1)
					cold = cold+1;								
			});*/
			col=colIndex+cold;//跳过RowNumber列和check列
			if(!divHtml){
				divHtml = arrayTd[col-1].innerHTML;
				rowspanObj = {tr:i,td:col,rowspan:rowspan}
			}else{
				var cellText = arrayTd[col-1].innerHTML;
				var addf=function(){ 
					rowspanObj["rowspan"] = rowspanObj["rowspan"]+1;
					removeObjs.push({tr:i,td:col});
					if(i==trCount-1)
						merge(rowspanObj,removeObjs);//执行合并函数
				};
				var mergef=function(){
					merge(rowspanObj,removeObjs);//执行合并函数
					divHtml = cellText;
					rowspanObj = {tr:i,td:col,rowspan:rowspan}
					removeObjs = [];
				};
				if(cellText == divHtml){
					if(colIndex!=cols[0]){ 
						var leftDisplay=arrayTd[col-2].style.display;//判断左边单元格值是否已display
						if(leftDisplay=='none')
							addf();	
						else
							mergef();							
					}else
						addf();											
				}else
					mergef();			
			}
		}
	});	
};

Ext.define('Ext.adms.lineChart', {
    extend: 'Ext.chart.Chart',
    xtype: 'xlinechart',
    animate: true,
    url: '',
    xName: '',
    yName: '',
    
    initComponent: function () {
        var me = this;
        me.store = Ext.create('Ext.data.Store', {
    	    autoLoad: true,
    	    fields: ['name','data', 'used', 'total'],
    	    proxy: {
    	        type: 'ajax',
    	        url: me.url,
    	        reader: {
    	            type: 'json',
                    idProperty: 'name',
                    totalProperty: 'total',
                    nameProperty:'cluster',
                    root: 'result'
    	        }
    	    }
    	});
        me.axes = [];
        me.axes.push({
            type: 'Numeric',
            position: 'left',
            fields: ['data'],
            label: {
                renderer: Ext.util.Format.numberRenderer('0,0')
            },
            title: me.yName,
            grid: true,
            minimum: 0
        });
        me.axes.push({
            type: 'Category',
            position: 'bottom',
            fields: ['name'],
            title: me.xName
        });
        var gridStore =  Ext.create('Ext.data.JsonStore', {
            fields: ['name', 'data'],
            data: []
        });
        
      
       var pieStore = Ext.create('Ext.data.JsonStore', {
            fields: ['name', 'data'],
            data: []
        });
       
       var grid = Ext.create('Ext.grid.Panel', {
           store: gridStore,
           id : 'inner-grid',
           height: 100,
           width: 280,
           columns: [
               {
                   text   : 'name',
                   dataIndex: 'name'
               },
               {
                   text   : 'data',
                   dataIndex: 'data'
               }
           ]
       });
       
       var pieChart = Ext.create('Ext.chart.Chart', {
           width: 100,
           height: 100,
           animate: false,
           store: pieStore,
           id : 'inner-pie',
           shadow: false,
           insetPadding: 0,
           theme: 'Base:gradients',
           series: [{
               type: 'pie',
               field: 'data',
               showInLegend: false,
               label: {
                   field: 'name',
                   display: 'rotate',
                   contrast: true,
                   font: '9px Arial'
               }
           }]
       });
        me.series = []
        me.series.push({
            type: 'line',
            axis: 'left',
            highlight: {
                size: 7,
                radius: 7
            },
            markerConfig: {
                type: 'circle',
                size: 4,
                radius: 4,
                'stroke-width': 0
            },
            //highlight: true,
            tips: {
           	 	trackMouse: true,
                width: 580,
                height: 170,
                layout: 'fit',
                items: {
                    xtype: 'container',
                    layout: 'hbox',
                    items: [pieChart, grid]
                },
                renderer: function(storeItem, item) {
                //renderer: function(klass, item) {
                	//var storeItem = item.storeItem;
                	                	
                	var used = Number(storeItem.get('used'));
                	var total = Number(storeItem.get('total'));
                	var data = storeItem.get('data');
                	var unused = total - used;
                	
                    gridData = [{
                        name: '已使用',
                        data: used
                    },
                    {
                    	name: '未使用',
                    	data: unused
                    },
                    {
                   	  	name:'总共',
                   	  	data:total
                     }];
                     
                     pieData = [{
                         name: '已使用',
                         data: used
                     },
                     {
                     	  name: '未使用',
                     	  data: unused
                     }];

                     this.setTitle("Information for " + storeItem.get('name') + '  使用率:' +  parseInt(data*100) / 100 + '%');
                     //Ext.getCmp('inner-pie').getStore().loadData(pieData);
                     pieStore.loadData(pieData);
                     gridStore.loadData(gridData);
                     //Ext.getCmp('inner-grid').getStore().loadData(gridData);
                }
            },
            label: {  
             	display: 'over',  
               	'text-anchor': 'middle',  
               	field: 'data',  
               	renderer: Ext.util.Format.numberRenderer('0.00'),  
               	orientation: 'vertical',  
               	color: '#333'  
               	},  
            style: { 'foreground-color': '#00f' },  
            showMarkers:true, 
            xField: 'name',
            yField: 'data'
            });
    	me.callParent();
        }
});


Ext.define('Ext.adms.testlineChart', {
    extend: 'Ext.chart.Chart',
    xtype: 'xtestlinechart',
    animate: true,
    url: '',
    xName: '',
    yName: '',
    dataField: "",
    dataArea: ['主站', '弹性计算','name','主站_detail', '弹性计算_detail'],
    initComponent: function () {
        var me = this;
        me.store = Ext.create('Ext.data.Store', {
    	    autoLoad: true,
    	    fields: me.dataArea,
    	    proxy: {
    	        type: 'ajax',
    	        url: me.url,
    	        reader: {
    	            type: 'json',
                    idProperty: 'name',
                    totalProperty: 'total',
                    root: 'result'
    	        }
    	    }
    	});
        me.legend = {
			position : 'right',
			itemSpacing:5,
			padding:5
		},
        me.axes = [];
        me.axes.push({
            type: 'Numeric',
            position: 'left',
            fields: me.dataField,
            label: {
                renderer: Ext.util.Format.numberRenderer('0.00')
            },
            title: me.yName,
            grid: true,
            minimum: 0
        });
        me.axes.push({
            type: 'Category',
            position: 'bottom',
            fields: ['name'],
            title: me.xName
        });
        me.series = []
        for (var field in me.dataField){
	        me.series.push({
	            type: 'line',
	            axis: 'left',
	            highlight: {
	                size: 7,
	                radius: 7
	            },
	            markerConfig: {
	                type: 'circle',
	                size: 4,
	                radius: 4,
	                'stroke-width': 0
	            },
	            tips: {
	              trackMouse: true,
	              renderer: Ext.util.Format.numberRenderer('0.00'),
	              width:  200,
	              height: 25,
	              itemId : field,
	              renderer: function(storeItem, item) {
	            	var title = me.dataField[this.itemId] + '使用率:' + storeItem.get(me.dataField[this.itemId]) + '%';
	                this.setTitle(title);
	              }
	            },
	            label: {  
	                display: 'over',  
	                'text-anchor': 'middle',  
	                field: 'data',  
	                renderer: Ext.util.Format.numberRenderer('0.00'),  
	                orientation: 'vertical',  
	                color: '#333'  
	            },  
	            
	            xField: 'name',
	            yField: me.dataField[field],
	        });
        }
        
        me.callParent();
    }
});



Ext.define('Ext.adms.multilinechart', {
    extend: 'Ext.chart.Chart',
    xtype: 'xmultilinechartlinechart',
    animate: true,
    url: '',
    xName: '',
    yName: '',
    dataField: "",
    dataArea: "",
    initComponent: function () {
        var me = this;
        me.store = Ext.create('Ext.data.Store', {
    	    autoLoad: true,
    	    fields: me.dataArea,
    	    proxy: {
    	        type: 'ajax',
    	        url: me.url,
    	        reader: {
    	            type: 'json',
                    idProperty: 'name',
                    totalProperty: 'total',
                    root: 'result'
    	        }
    	    }
    	});
        
        me.legend = {
			position : 'right',
			itemSpacing:5,
			padding:5
		},
        me.axes = [];
        me.axes.push({
            type: 'Numeric',
            position: 'left',
            fields: me.dataField,
            label: {
                renderer: Ext.util.Format.numberRenderer('0.00')
            },
            title: me.yName,
            grid: true,
            minimum: 0
        });
        me.axes.push({
            type: 'Category',
            position: 'bottom',
            fields: ['name'],
            title: me.xName
        });
        me.series = []
        
        for (var field in me.dataField){
        	var gridStore =  Ext.create('Ext.data.JsonStore', {
	             fields: ['name', 'data'],
	             data: []
	         });
             
           
	        var pieStore = Ext.create('Ext.data.JsonStore', {
	             fields: ['name', 'data'],
	             data: []
	         });
	        
	        var grid = Ext.create('Ext.grid.Panel', {
                store: gridStore,
                id : 'inner-grid-'+field,
                height: 100,
                width: 280,
                columns: [
                    {
                        text   : 'name',
                        dataIndex: 'name'
                    },
                    {
                        text   : 'data',
                        dataIndex: 'data'
                    }
                ]
            });
	        
	        var pieChart = Ext.create('Ext.chart.Chart', {
                width: 100,
                height: 100,
                id : 'inner-pie-'+field,
                animate: false,
                store: pieStore,
                shadow: false,
                insetPadding: 0,
                theme: 'Base:gradients',
                series: [{
                    type: 'pie',
                    field: 'data',
                    showInLegend: false,
                    label: {
                        field: 'name',
                        display: 'rotate',
                        contrast: true,
                        font: '9px Arial'
                    }
                }]
            });
        	me.series.push({
	            type: 'line',
	            axis: 'left',
	            highlight: {
	                size: 7,
	                radius: 7
	            },
	            markerConfig: {
	                type: 'circle',
	                size: 4,
	                radius: 4,
	                'stroke-width': 0
	            },
	            
	            tips: {	            
	            	 itemId : field,
	            	 trackMouse: true,
	                    width: 580,
	                    height: 170,
	                    layout: 'fit',
	                    items: {
	                        xtype: 'container',
	                        layout: 'hbox',
	                        items: [pieChart, grid]
	                    },
	              
	                renderer: function(klass, item) {
	            	  var storeItem = item.storeItem;
                      var detail = storeItem.get(me.dataField[this.itemId] + '_detail');
                          gridData = [{
                              name: '已使用',
                              data: detail['used'],
                          },{
                          	  name: '未使用',
                          	  data: detail['unused'],
                          },
                          {
                        	  name:'总共',
                        	  data:detail['total'],
                          }
                          ];
                          
                          pieData = [{
                              name: '已使用',
                              data: detail['used'],
                          },{
                          	  name: '未使用',
                          	  data: detail['unused'],
                          }];
                          
                      this.setTitle("Information for " + me.dataField[this.itemId] + '  使用率:' +  storeItem.get(me.dataField[this.itemId]) + '%');
                      Ext.getCmp('inner-pie-'+this.itemId).getStore().loadData(pieData);
                      Ext.getCmp('inner-grid-'+this.itemId).getStore().loadData(gridData);

//                      gridStore.loadData(gridData);
                  }
	            },
	            label: {  
	                display: 'over',  
	                'text-anchor': 'middle',  
	                field: me.dataField[field],  
	                renderer: Ext.util.Format.numberRenderer('0.00'),  
	                orientation: 'vertical',  
	                color: '#333'  
	            },  
	            
	            xField: 'name',
	            yField: me.dataField[field],
	        }); 
        }
        
        me.callParent();
    }
});

Ext.define('Ext.adms.stackcolumnChart', {
    extend: 'Ext.chart.Chart',
    xtype: 'xstackcolumnchart',
    animate: true,
    url: '',
    xName: '',
    yName: '', 
    xdatafield: '',
    xsign: '',
    initComponent: function () {
        var me = this;
        me.store = Ext.create('Ext.data.Store', {
    	    autoLoad: true,
    	    fields:  me.xdatafield.concat(['time']).concat(me.xsign),
    	    
    	    proxy: {
    	        type: 'ajax',
    	        url: me.url,
    	        reader: {
    	            type: 'json',
                    idProperty: 'time',
                    totalProperty: 'total',
                    root: 'result'
    	        }
    	    }
    	});
        me.legend = {
            position: 'right'
        },  
        me.axes = [];
        me.axes.push({
            type: 'Numeric',
            position: 'left',
            fields: me.xdatafield,
            title: me.yName,
            grid: true,
            label: {
                renderer: Ext.util.Format.numberRenderer('0')
            },
          
        }); 
        me.axes.push({
            type: 'Category',
            position: 'bottom',
            fields: ['time'],
            title: me.xName
        });
        me.series = [];
        me.series.push({
            type: 'column',
            axis: 'left',
            gutter: 80,
            xField: 'year',
            yField: me.xdatafield,
            stacked: true,
            tips: {
                trackMouse: true,
                width: 65,
                height: 28,
                renderer: function(storeItem, item) {
                    this.setTitle('[ '+ String(item.value[1])+' ]');
                }
            },
            /*
        	label: {
        	  display: 'over',
              field: me.xsign,
              renderer: Ext.util.Format.numberRenderer('0'),
              orientation: 'horizon',
              color: '#333',
              'text-anchor': 'middle'
          	
          },*/
        
        });
        
        me.callParent();
    }
});

Ext.define('Ext.adms.singlelineChart', {
    extend: 'Ext.chart.Chart',
    xtype: 'x1linechart',
    animate: true,
    shadow: false,
    smooth: true,
    url: '',
    xName: '',
    yName: '',
    data1: '',
    data2: '',

    initComponent: function () {
        var me = this;
        me.store = Ext.create('Ext.data.Store', {
    	    autoLoad: true,
    	    fields: ['name','data', 'total', 'used'],
    	    proxy: {
    	        type: 'ajax',
    	        url: me.url,
    	        reader: {
    	            type: 'json',
                    idProperty: 'name',
                    totalProperty: 'total',
                    nameProperty:'cluster',
                    root: 'result'
    	        }
    	    }
    	});
        me.axes = [];
        me.axes.push({
            type: 'Numeric',
            position: 'left',
            fields: ['data'],
            label: {
                renderer: Ext.util.Format.numberRenderer('0')
            },
            title: me.yName,
            grid: true,
            minimum: 0
        });
        me.axes.push({
            type: 'Category',
            position: 'bottom',
            fields: ['name'],
            title: me.xName,
            label: {
                rotate: {
                    degrees: 30
                }
            }
        });
        me.series = []
        me.series.push({
            type: 'line',
            axis: 'left',
            highlight: {
                size: 7,
                radius: 7
            },
            markerConfig: {
                type: 'circle',
                size: 4,
                radius: 4,
                'stroke-width': 0
            },
            //highlight: true,
            tips: {
              trackMouse: true,
              renderer: Ext.util.Format.numberRenderer('0'),
              width:  200,
              height: 25,
              renderer: function(storeItem, item) {
                this.setTitle(me.data1 +':' + storeItem.get('used') + ' ,'+me.data2+': ' + storeItem.get('total'));
              }
            },
            label: {  
                display: 'over',  
                'text-anchor': 'middle',  
                field: 'data',  
                renderer: Ext.util.Format.numberRenderer('0'),  
                orientation: 'vertical',  
                color: '#333'  
            },  
            style: { 
            	'stroke-width': 2,
            	'foreground-color': '#00f' },  
            	
            showMarkers:true, 
            xField: 'name',
            yField: 'data'
        });
        me.callParent();
    }
});


Ext.define('Ext.adms.manylineChart', {
    extend: 'Ext.chart.Chart',
    xtype: 'x2linechart',
    animate: true,
    shadow: false,
    smooth: true,
    url: '',
    xName: '',
    yName: '',
    xdata1: '',
    xdata2: '',
    xdatafield: '',
    initComponent: function () {
        var me = this;
        me.store = Ext.create('Ext.data.Store', {
    	    autoLoad: true,
    	    fields: me.xdatafield.concat(['name', 'total1', 'used1',  'total2', 'used2', 'total3', 'used3']),
    	    proxy: {
    	        type: 'ajax',
    	        url: me.url,
    	        reader: {
    	            type: 'json',
                    idProperty: 'name',
                    totalProperty: 'total',
                    nameProperty:'cluster',
                    root: 'result'
    	        }
    	    }
    	});
        me.legend = {
                position: 'right'
            };
        me.axes = [];
        me.axes.push({
            type: 'Numeric',
            position: 'left',
            fields: me.xdatafield,
            label: {
                renderer: Ext.util.Format.numberRenderer('0.0')
            },
            title: me.yName,
            grid: true,
            minimum: 0,
            maximum: 100
        });
        me.axes.push({
            type: 'Category',
            position: 'bottom',
            fields: ['name'],
            title: me.xName,
            label: {
                rotate: {
                    degrees: 30
                }
            }
        });
        me.series = []
        me.series.push({
            type: 'line',
            axis: 'left',
            highlight: {
                size: 3,
                radius: 3
            },
            markerConfig: {
                type: 'circle',
                size: 4,
                radius: 4,
                'stroke-width': 0
            },
            //highlight: true,
            tips: {
              trackMouse: true,
              renderer: Ext.util.Format.numberRenderer('0.0'),
              width:  200,
              height: 25,
              renderer: function(storeItem, item) {
                this.setTitle('使用率: '+ storeItem.get(me.xdatafield[0])+ ' 总端口: ' + storeItem.get('total1') + '  使用数: '+  storeItem.get('used1'));
              }
            },
            style: { 
            	'stroke-width': 2,
            	'foreground-color': '#00f' 
            },  
            showMarkers:true, 
            xField: 'name',
            yField: me.xdatafield[0],
        });
        
        me.series.push({
            type: 'line',
            axis: 'left',
            highlight: {
                size: 3,
                radius: 3
            },
            markerConfig: {
                type: 'circle',
                size: 4,
                radius: 4,
                'stroke-width': 0,
                'fill':'#FF0000'
            },
            //highlight: true,
            tips: {
              trackMouse: true,
              renderer: Ext.util.Format.numberRenderer('0.00'),
              width:  200,
              height: 25,
              renderer: function(storeItem, item) {
            	  this.setTitle('总端口: ' + storeItem.get('total2') + '  使用数: '+  storeItem.get('used2'));
              }
            },
            /*
            label: {  
                display: 'over',  
                'text-anchor': 'middle',  
                field: me.xdatafield[1],  
                renderer: Ext.util.Format.numberRenderer('0.0'),  
                orientation: 'vertical',  
                color: '#333' , 
            },*/  
            style: {
            	'stroke-width': 2,
            	'stroke': '#FF0000',
            },  
            showMarkers:true, 
            xField: 'name',
            yField: me.xdatafield[1],
        });
        me.callParent();
    }
});

Ext.define('Ext.adms.xxlineChart', {
    extend: 'Ext.chart.Chart',
    xtype: 'xxlinechart',
    animate: true,
    shadow: false,
    smooth: true,
    url: '',
    xName: '',
    yName: '',
    xdatafield: '',
    xfield: '',
    initComponent: function () {
        var me = this;
        me.store = Ext.create('Ext.data.Store', {
    	    autoLoad: true,
    	    fields: me.xdatafield.concat(['name']).concat(me.xfield),   
    	    proxy: {
    	        type: 'ajax',
    	        url: me.url,
    	        reader: {
    	            type: 'json',
                    idProperty: 'name',
                    totalProperty: 'total',
                    nameProperty:'cluster',
                    root: 'result'
    	        }
    	    }
    	});
        
        me.legend = {
			position: 'right',
			itemSpacing:5,
			padding:5
		};
        me.axes = [];
        me.axes.push({
            type: 'Numeric',
            position: 'left',
            fields: me.xdatafield,
            label: {
                renderer: Ext.util.Format.numberRenderer('0.00')
            },
            title: me.yName,
            grid: true,
            minimum: 0
        });
        me.axes.push({
            type: 'Category',
            position: 'bottom',
            fields: ['name'],
            title: me.xName,
            label: {
                rotate: {
                    degrees: 30
             }
            }
        });
        
        me.series = [];
        for (var field in me.xdatafield){
        	me.series.push({
	            type: 'line',
	            axis: 'left',
	            highlight: {
	                size: 7,
	                radius: 7
	            },
	            markerConfig: {
	                type: 'circle',
	                size: 4,
	                radius: 4,
	                'stroke-width': 0
	            },
	            tips: {
	              trackMouse: true,
	              renderer: Ext.util.Format.numberRenderer('0,0'),
	              width:  200,
	              height: 25,
	              itemId : field,
	              renderer: function(storeItem, item) {
	            	var bw = storeItem.get(me.xfield[this.itemId]);
	            	var usage = 0;
	            	var title;
	            	var tbw = storeItem.get(me.xdatafield[this.itemId]);
	            	
	            	if (bw != 0){
	            		usage = 1.0 * tbw / bw * 100;
	            	}
	            	if (bw == 0 && tbw != 0){
	            		title = '峰值流量: ' + tbw + 'G';
	            	}else {
	            		title = '当前带宽: '+ bw +'G' + ' 使用率: ' + usage.toFixed(2) + '%';
	            	}	            		
	            	this.setTitle(title);
	              }
	            },
	            
	            label: {  
	                display: 'none',  
	                'text-anchor': 'center',  
	                field: me.xdatafield[field],  
	                renderer: Ext.util.Format.numberRenderer('0.00'),  
	                orientation: 'vertical',  
	                color: '#333'  
	            },
	             
	            style: { 
	            	'stroke-width': 2,
	            	'foreground-color': '#00f' 
	            },  
	            showMarkers:true, 
	            xField: 'name',
	            yField: me.xdatafield[field]
        	});
        }
        
        me.callParent();
    }
});


Ext.define('Ext.adms.xx1lineChart', {
    extend: 'Ext.chart.Chart',
    xtype: 'xx1linechart',
    animate: true,
    shadow: false,
    smooth: true,
    url: '',
    xName: '',
    yName: '',
    xdatafield: '',
    initComponent: function () {
        var me = this;
        me.store = Ext.create('Ext.data.Store', {
    	    autoLoad: true,
    	    fields: me.xdatafield.concat(['name']),
    	    proxy: {
    	        type: 'ajax',
    	        url: me.url,
    	        reader: {
    	            type: 'json',
                    idProperty: 'name',
                    totalProperty: 'total',
                   // nameProperty:'cluster',
                    root: 'result'
    	        }
    	    }
    	});

        me.axes = [];
        me.axes.push({
            type: 'Numeric',
            position: 'left',
            fields: me.xdatafield,
            label: {
                renderer: Ext.util.Format.numberRenderer('0.00')
            },
            title: me.yName,
            grid: true,
            minimum: 0
        });
        me.axes.push({
            type: 'Category',
            position: 'bottom',
            fields: ['name'],
            title: me.xName,
            label: {
                rotate: {
                    degrees: 30
                }
            }
        
        });
        me.series = []
        for (var field in me.xdatafield){
        	me.series.push({
	            type: 'line',
	            axis: 'left',
	            highlight: {
	                size: 7,
	                radius: 7
	            },
	            markerConfig: {
	                type: 'circle',
	                size: 4,
	                radius: 4,
	                'stroke-width': 0
	            },
	            tips: {
	              trackMouse: true,
	              renderer: Ext.util.Format.numberRenderer('0,0'),
	              width:  150,
	              height: 25,
	              itemId : field,
	              renderer: function(storeItem, item) {  
	            	var title = me.xdatafield[this.itemId];
	                this.setTitle(title+": "+storeItem.get(me.xdatafield[this.itemId])+'G');
	              }
	            },
	            label: {  
	                display: 'over',  
	                'text-anchor': 'middle',  
	                field: me.xdatafield[field],  
	                renderer: Ext.util.Format.numberRenderer('0.00'),  
	                orientation: 'vertical',  
	                color: '#333'  
	            }, 
	            style: { 'foreground-color': '#00f' },  
	            showMarkers:true, 
	            xField: 'name',
	            yField: me.xdatafield[field],
	        });
        }        
        me.callParent();
    }
});

Ext.define('Ext.chart.theme.StackedColumnTheme', {
    extend: 'Ext.chart.theme.Base',
    constructor: function(config) {
        this.callParent([Ext.apply({ 
           colors: ['red','#99FFFF']
        }, config)]);
    }
});

Ext.define('Ext.chart.theme.ColumnTheme', {
    extend: 'Ext.chart.theme.Base',
    constructor: function(config) {
        this.callParent([Ext.apply({ 

           colors: ['#99FFFF']

        }, config)]);
    }
});

Ext.define('Ext.adms.XMuiltColumnChart', {
    extend: 'Ext.chart.Chart',
    xtype: 'xxcolumnchart',
    animate: true,
    theme: 'StackedColumnTheme',
    url: '',
    xName: '',
    yName: '',
    xdatafield: '',
    xtitle: '',
    serieClickCallback : null,
    initComponent: function () {
        var me = this;
        me.store = Ext.create('Ext.data.Store', {
    	    autoLoad: true,
    	    fields: me.xdatafield.concat(['name']),
    	    proxy: {
    	        type: 'ajax',
    	        url: me.url,
    	        reader: {
    	            type: 'json',
                    idProperty: 'name',
                    totalProperty: 'total',
                    root: 'result'
    	        }
    	    }
    	});
        me.legend = {
                position: 'right',
                padding:3
        },  
        me.axes = [];
        me.axes.push({
            type: 'Numeric',
            position: 'left',
            fields: me.xdatafield,
            label: {
                renderer: Ext.util.Format.numberRenderer('0,0')
            },
            title: me.yName,
            grid: true,
            minimum: 0
        });
        me.axes.push({
            type: 'Category',
            position: 'bottom',
            fields: ['name'],
            title: me.xName,
        });
        me.series = [];
        me.series.push({
            type: 'column',
            axis: 'left',
            stacked: true,
            gutter: 180,
            tips: {
              trackMouse: true,
              width: 220,
              height: 25,
              renderer: function(storeItem, item) {
            	var unuse = storeItem.get(me.xdatafield[1]);
            	var use = storeItem.get(me.xdatafield[0]);
            	
            	if (isNaN(unuse)){
            		this.setTitle(me.xdatafield[0]+': '+ storeItem.get(me.xdatafield[0]) 
                    		+ 'G ');
            	}else {
            		var bw = unuse + use;
            		this.setTitle(me.xdatafield[0]+': '+ storeItem.get(me.xdatafield[0]) 
                    		+ 'G ' + '带宽'+': '+ bw +'G');           	
            	}     
              }
            },
            
            label: {
            	display: 'insideEnd',
                field: 'value',
                renderer: Ext.util.Format.numberRenderer('0'),
                orientation: 'vertical',
                color: 'black',
                'text-anchor': 'middle'
            },
            listeners : {  
                itemclick : function(o) {         	
                	var title = me.xtitle;
                	var rec = o.value[0];
                    me.serieClickCallback(title, rec); 
                }  
            },
            style: { 
            	color:'#FF0000',
            },
            xField: 'name',
            yField: me.xdatafield,
        });
        
        me.callParent();
    }
});



Ext.define('Ext.adms.admslineChart', {
    extend: 'Ext.chart.Chart',
    xtype: 'admslinechart',
    animate: true,
    shadow: false,
    smooth: true,
    url: '',
    xName: '',
    yName: '',
    xdatafield: '',
    xfield: '',
    xtag: '',
    xcolor: ['#FF4040', '#0000FF', '#99FF00'],
    initComponent: function () {
        var me = this;
        me.store = Ext.create('Ext.data.Store', {
    	    autoLoad: true,
    	    fields: me.xdatafield.concat(['name']).concat(me.xfield).concat(me.xtag),   
    	    proxy: {
    	        type: 'ajax',
    	        url: me.url,
    	        reader: {
    	            type: 'json',
                    idProperty: 'name',
                    totalProperty: 'total',
                    nameProperty:'cluster',
                    root: 'result'
    	        }
    	    }
    	});
        
        me.legend = {
			position: 'right'
		};
        me.axes = [];
        me.axes.push({
            type: 'Numeric',
            position: 'left',
            fields: me.xdatafield,
            label: {
                renderer: Ext.util.Format.numberRenderer('0')
            },
            title: me.yName,
            grid: true,
            minimum: 0
        });
        me.axes.push({
            type: 'Category',
            position: 'bottom',
            fields: ['name'],
            title: me.xName,
            label: {
                rotate: {
                    degrees: 45
             }
            }
        });
        
        me.series = [];
        for (var field in me.xdatafield){
        	me.series.push({
	            type: 'line',
	            axis: 'left',
	            highlight: {
	                size: 7,
	                radius: 7
	            },
	            markerConfig: {
	                type: 'circle',
	                size: 4,
	                radius: 4,
	                'stroke-width': 0,
	                'fill': me.xcolor[field],
	            },
	            tips: {
	              trackMouse: true,
	              renderer: Ext.util.Format.numberRenderer('0,0'),
	              width:  300,
	              height: 25,
	              itemId : field,
	              renderer: function(storeItem, item) {	            	
	            	data0 = storeItem.get(me.xfield[this.itemId]);
	            	data1 = storeItem.get(me.xtag[this.itemId]);
	            	if (data0 != "undefined"){
	            		title0 = me.xfield[this.itemId]+ ': ' + data0;	            		
	            	}
	            	if (data1 != "undefined"){
	            		title1 = me.xtag[this.itemId]+ ': ' + data1;
	            	}
	            	
	            	title = title0 + ' ' + title1;
	            	this.setTitle(title);
	              }
	            },
	            
	            label: {  
	                display: 'none',  
	                'text-anchor': 'center',  
	                field: me.xdatafield[field],  
	                renderer: Ext.util.Format.numberRenderer('0.0'),  
	                orientation: 'vertical',  
	                color: '#333'  
	            },
	             
	            style: { 
	            	'stroke-width': 2,
	            	'foreground-color': '#00f', 
	            	'stroke': me.xcolor[field],
	            },  
	            showMarkers:true, 
	            xField: 'name',
	            yField: me.xdatafield[field]
        	});
        }
        
        me.callParent();
    }
});



Ext.define('Ext.adms.EditPropertyGrid', {
    extend: 'Ext.grid.PropertyGrid',
    xtype: 'xpropertygrid',
    padding:10,
	hideHeaders :true,
	width: 400,
	sortableColumns:false,
	listeners: {
		beforeedit : function(e){
			e.cancel = true;  
	    	return true;
		}
	}
});

/**
 * 时间输入框, 三个整数框分别输入时,分,秒.
 * @author wangzilong
 * update Ext - 4.1 2012/04/27
 */
Ext.define('MyApp.ux.TimePickerField', {
    extend: 'Ext.form.field.Base',
    alias: 'widget.timepicker',
    alternateClassName: 'Ext.form.field.TimePickerField',
    requires: ['Ext.form.field.Number'],
    // 隐藏BaseField的输入框 , hidden basefield's input
    inputType: 'hidden',
    style: 'padding:4px 0 0 0;margin-bottom:0px',
    /**
    * @cfg {String} value
    * initValue, format: 'H:i:s'
    */
    value: null,
    /**
    * @cfg {Object} spinnerCfg
    * 数字输入框参数, number input config
    */
    spinnerCfg: {
      width: 50
    },
    /** Override. */
    initComponent: function() {
      var me = this;
      me.value = me.value || Ext.Date.format(new Date(), 'H:i:s');
      me.callParent();// called setValue
      me.spinners = [];
      var cfg = Ext.apply({}, me.spinnerCfg, {
            readOnly: me.readOnly,
            disabled: me.disabled,
            style: 'float: left',
            listeners: {
                change: {
                    fn: me.onSpinnerChange,
                    scope: me
                }
            }
        });
      me.hoursSpinner = Ext.create('Ext.form.field.Number', Ext.apply({}, cfg, {
              minValue: 0,
              maxValue: 23
          }));
      me.minutesSpinner = Ext.create('Ext.form.field.Number', Ext.apply({}, cfg, {
              minValue: 0,
              maxValue: 59
          }));
      // TODO 使用timeformat 判断是否创建秒输入框, maybe second field is not always need.
      me.secondsSpinner = Ext.create('Ext.form.field.Number', Ext.apply({}, cfg, {
              minValue: 0,
              maxValue: 59
          }));
      me.spinners.push(me.hoursSpinner, me.minutesSpinner, me.secondsSpinner);
    },
    /**
      * @private
      * Override.
      */
    onRender: function() {
      var me = this, spinnerWrapDom, spinnerWrap;
      me.callParent(arguments);
      // render to original BaseField input td
      // spinnerWrap = Ext.get(Ext.DomQuery.selectNode('div', this.el.dom)); // 4.0.2
      spinnerWrapDom = Ext.dom.Query.select('td', this.getEl().dom)[1]; // 4.0 ->4.1 div->td
      spinnerWrap = Ext.get(spinnerWrapDom);
      me.callSpinnersFunction('render', spinnerWrap);
      Ext.core.DomHelper.append(spinnerWrap, {
            tag: 'div',
            cls: 'x-form-clear-left'
        });
      this.setRawValue(this.value);
    },
    _valueSplit: function(v) {
      if(Ext.isDate(v)) {
          v = Ext.Date.format(v, 'H:i:s');
      }
      var split = v.split(':');
      return {
          h: split.length > 0 ? split[0] : 0,
          m: split.length > 1 ? split[1] : 0,
          s: split.length > 2 ? split[2] : 0
      };
    },
    onSpinnerChange: function() {
      if(!this.rendered) {
          return;
      }
      this.fireEvent('change', this, this.getValue(), this.getRawValue());
    },
    // 依次调用各输入框函数, call each spinner's function
    callSpinnersFunction: function(funName, args) {
      for(var i = 0; i < this.spinners.length; i++) {
          this.spinners[i][funName](args);
      }
    },
    // @private get time as object,
    getRawValue: function() {
      if(!this.rendered) {
          var date = this.value || new Date();
          return this._valueSplit(date);
      } else {
          return {
              h: this.hoursSpinner.getValue(),
              m: this.minutesSpinner.getValue(),
              s: this.secondsSpinner.getValue()
          };
      }
    },
    // private
    setRawValue: function(value) {
      value = this._valueSplit(value);
      if(this.hoursSpinner) {
          this.hoursSpinner.setValue(value.h);
          this.minutesSpinner.setValue(value.m);
          this.secondsSpinner.setValue(value.s);
      }
    },
    // overwrite
    getValue: function() {
      var v = this.getRawValue();
      return Ext.String.leftPad(v.h, 2, '0') + ':' + Ext.String.leftPad(v.m, 2, '0') + ':'
        + Ext.String.leftPad(v.s, 2, '0');
    },
    // overwrite
    setValue: function(value) {
      this.value = Ext.isDate(value) ? Ext.Date.format(value, 'H:i:s') : value;
      if(!this.rendered) {
          return;
      }
      this.setRawValue(this.value);
      this.validate();
    },
    // overwrite
    disable: function() {
      this.callParent(arguments);
      this.callSpinnersFunction('disable', arguments);
    },
    // overwrite
    enable: function() {
      this.callParent(arguments);
      this.callSpinnersFunction('enable', arguments);
    },
    // overwrite
    setReadOnly: function() {
      this.callParent(arguments);
      this.callSpinnersFunction('setReadOnly', arguments);
    },
    // overwrite
    clearInvalid: function() {
      this.callParent(arguments);
      this.callSpinnersFunction('clearInvalid', arguments);
    },
    // overwrite
    isValid: function(preventMark) {
      return this.hoursSpinner.isValid(preventMark) && this.minutesSpinner.isValid(preventMark)
        && this.secondsSpinner.isValid(preventMark);
    },
    // overwrite
    validate: function() {
      return this.hoursSpinner.validate() && this.minutesSpinner.validate() && this.secondsSpinner.validate();
    }
});

Ext.define('MyApp.ux.DateTimePicker', {
      extend: 'Ext.picker.Date',
      alias: 'widget.datetimepicker',
      todayText: '现在',
      timeLabel: '时间',
      requires: ['MyApp.ux.TimePickerField'],
      initComponent: function() {
          // keep time part for value
          var value = this.value || new Date();
          this.callParent();
          this.value = value;
      },
      onRender: function(container, position) {
          if(!this.timefield) {
              this.timefield = Ext.create('MyApp.ux.TimePickerField', {
                    fieldLabel: this.timeLabel,
                    labelWidth: 40,
                    value: Ext.Date.format(this.value, 'H:i:s')
                });
          }
          this.timefield.ownerCt = this;
          this.timefield.on('change', this.timeChange, this);
          this.callParent(arguments);
          var table = Ext.get(Ext.DomQuery.selectNode('table', this.el.dom));
          var tfEl = Ext.core.DomHelper.insertAfter(table, {
                tag: 'div',
                style: 'border:0px;',
                children: [{
                      tag: 'div',
                      cls: 'x-datepicker-footer ux-timefield'
                  }]
            }, true);
          this.timefield.render(this.el.child('div div.ux-timefield'));
          var p = this.getEl().parent('div.x-layer');
          if(p) {
              p.setStyle("height", p.getHeight() + 31);
          }
      },
      // listener 时间域修改, timefield change
      timeChange: function(tf, time, rawtime) {
          // if(!this.todayKeyListener) { // before render
          this.value = this.fillDateTime(this.value);
          // } else {
          // this.setValue(this.value);
          // }
      },
      // @private
      fillDateTime: function(value) {
          if(this.timefield) {
              var rawtime = this.timefield.getRawValue();
              value.setHours(rawtime.h);
              value.setMinutes(rawtime.m);
              value.setSeconds(rawtime.s);
          }
          return value;
      },
      // @private
      changeTimeFiledValue: function(value) {
          this.timefield.un('change', this.timeChange, this);
          this.timefield.setValue(this.value);
          this.timefield.on('change', this.timeChange, this);
      },
      /* TODO 时间值与输入框绑定, 考虑: 创建this.timeValue 将日期和时间分开保存. */
      // overwrite
      setValue: function(value) {
          this.value = value;
          this.changeTimeFiledValue(value);
          return this.update(this.value);
      },
      // overwrite
      getValue: function() {
          return this.fillDateTime(this.value);
      },
      // overwrite : fill time before setValue
      handleDateClick: function(e, t) {
          var me = this,
              handler = me.handler;
          e.stopEvent();
          if(!me.disabled && t.dateValue && !Ext.fly(t.parentNode).hasCls(me.disabledCellCls)) {
              me.doCancelFocus = me.focusOnSelect === false;
              me.setValue(this.fillDateTime(new Date(t.dateValue))); // overwrite: fill time before setValue
              delete me.doCancelFocus;
              me.fireEvent('select', me, me.value);
              if(handler) {
                  handler.call(me.scope || me, me, me.value);
              }
              me.onSelect();
          }
      },
      // overwrite : fill time before setValue
      selectToday: function() {
          var me = this,
              btn = me.todayBtn,
              handler = me.handler;
          if(btn && !btn.disabled) {
              // me.setValue(Ext.Date.clearTime(new Date())); //src
              me.setValue(new Date());// overwrite: fill time before setValue
              me.fireEvent('select', me, me.value);
              if(handler) {
                  handler.call(me.scope || me, me, me.value);
              }
              me.onSelect();
          }
          return me;
      }
  });


Ext.define('MyApp.ux.DateTimeField', {
      extend: 'Ext.form.field.Date',
      alias: 'widget.datetimefield',
      requires: ['MyApp.ux.DateTimePicker'],
      initComponent: function() {
          this.format = this.format;
          this.callParent();
      },
      // overwrite
      createPicker: function() {
          var me = this,
              format = Ext.String.format;
          return Ext.create('MyApp.ux.DateTimePicker', {
                ownerCt: me.ownerCt,
                renderTo: document.body,
                floating: true,
                hidden: true,
                focusOnShow: true,
                minDate: me.minValue,
                maxDate: me.maxValue,
                disabledDatesRE: me.disabledDatesRE,
                disabledDatesText: me.disabledDatesText,
                disabledDays: me.disabledDays,
                disabledDaysText: me.disabledDaysText,
                format: me.format,
                showToday: me.showToday,
                startDay: me.startDay,
                minText: format(me.minText, me.formatDate(me.minValue)),
                maxText: format(me.maxText, me.formatDate(me.maxValue)),
                listeners: {
                    scope: me,
                    select: me.onSelect
                },
                keyNavConfig: {
                    esc: function() {
                        me.collapse();
                    }
                }
            });
      }
  });