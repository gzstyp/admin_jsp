<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>
<meta http-equiv="pragma" content="no-cache">
<meta http-equiv="cache-control" content="no-cache">
<meta http-equiv="expires" content="0">
<div class="row">
    <div class="col-xs-12">
        <!-- PAGE CONTENT BEGINS -->
        <div class="row">
            <div class="col-xs-12">
                <div class="clearfix">
                    <table class="no-border" style="display:inline">
                        <tr>
                            <shiro:hasPermission name="role_btn_listData">
                            <td>
                                角色名称
                            </td>
                            <td style="padding: 0px 0px 0px 6px;">
                                <div class="input-group">
                                    <input type="text" id="key_role_name" class="form-control search-query" placeholder="角色关键字" />
                                    <span class="input-group-btn">
                                    <button type="button" class="btn btn-inverse btn-white" id="btnSearch">
                                        <span class="ace-icon fa fa-search bigger-110"></span>
                                        搜索
                                    </button>
                                </span>
                                </div>
                            </td>
                            </shiro:hasPermission>
                            <shiro:hasPermission name="role_btn_add">
                            <td>
                                <div class="input-group">
                                <span class="input-group-btn">
                                    <button type="button" class="btn btn-inverse btn-white" id="btnAdd">
                                        <span class="ace-icon glyphicon glyphicon-plus bigger-110"></span>
                                        添加
                                    </button>
                                </span>
                                </div>
                            </td>
                            </shiro:hasPermission>
                            <shiro:hasPermission name="role_btn_delByKeys">
                            <td>
                                <div class="input-group">
                                <span class="input-group-btn">
                                    <button type="button" class="btn btn-inverse btn-white" id="btnDel">
                                        <span class="fa fa-trash red2 bigger-110"></span>
                                        删除
                                    </button>
                                </span>
                                </div>
                            </td>
                            </shiro:hasPermission>
                        </tr>
                    </table>
                    <shiro:hasPermission name="role_btn_listData">
                    <div class="hidden-480 pull-right tableTools-container"></div>
                    </shiro:hasPermission>
                </div>
                <shiro:hasPermission name="role_btn_listData">
                <table id="tableListRole" class="table table-striped table-bordered table-hover"></table>
                </shiro:hasPermission>
            </div>
        </div>
        <!-- PAGE CONTENT ENDS -->
    </div>
</div>
<div id="div_role_edit" style="display:none;padding:20px 0px;">
    <form class="form-horizontal" id="form_role_edit" role="form">
        <label class="col-sm-3 control-label no-padding-right" for="role_name"><div class="hr-1"></div>角色名称</label>
        <div class="col-sm-7">
            <input type="text" id="role_name" placeholder="角色名称" class="form-control"/>
        </div>
        <label class="col-sm-3 control-label no-padding-right" for="role_flag"><div class="hr-4"></div>角色标识</label>
        <div class="col-sm-7"><div class="hr-4"></div><%--input--%>
            <input type="text" id="role_flag" placeholder="角色标识" class="form-control" />
        </div>
    </form>
</div>
<div id="divKeyColumns" style="display:none;padding:1px 0px;"></div>
<div id="div_role_menu" style="display:none;padding:2px 2px 2px 0px">
    <form class="form-horizontal">
        <div class="col-sm-12">
            <ul id="treeRoleMenu" class="ztree"></ul>
        </div>
    </form>
</div>
<input type="hidden" id="input_role_edit_keyId"/><%--编辑时用的id--%>
<script type="text/javascript">
    var scripts = [null,null];
    $('.page-content-area').ace_ajax('loadScripts',scripts,function(){
        var tableDom = '#tableListRole';
        var checkOption = false;
        $(function(){
            <shiro:hasPermission name="role_btn_listData">
            var urlRoute = '/role/';/*请求controller层的url*/
            var notAuthorized = urlRoute + "notAuthorized";
            var getList = urlRoute + 'listData';/*获取菜单列表,此处不需要添加的,已在请求的url添加了前缀*/
            <shiro:hasPermission name="role_btn_add">
            var urlAdd = urlRoute + 'add';/*添加*/
            </shiro:hasPermission>
            <shiro:hasPermission name="role_row_edit">
            var urlEdit = urlRoute + 'edit';/*编辑*/
            </shiro:hasPermission>
            <shiro:hasPermission name="role_row_delById">
            var urlDelById = urlRoute + 'delById';/*根据id删除对应的数据*/
            </shiro:hasPermission>
            <shiro:hasPermission name="role_btn_delByKeys">
            var urlDelByKeys = urlRoute + 'delByKeys';/*批量删除*/
            </shiro:hasPermission>
            <shiro:hasPermission name="role_row_delEmptyMenu">
            var urlDelEmptyMenu = urlRoute + 'delEmptyMenu';/*行按钮清空菜单*/
            </shiro:hasPermission>
            <shiro:hasPermission name="role_row_getRoleMenu">
            var urlGetRoleMenu = urlRoute + 'getRoleMenu';/*根据指定roleId获取菜单用于分配私有菜单*/
            </shiro:hasPermission>
            <shiro:hasPermission name="role_row_saveRoleMenu">
            var urlSaveRoleMenu = urlRoute + 'saveRoleMenu';/*保存角色菜单*/
            </shiro:hasPermission>
            var thisTable = pageDataTable.initDataTable({
                tableDom : tableDom,
                sAjaxSource: getList,
                fnServerParams : function(params){
                    params.push({"name":"role_name","value":$("#key_role_name").val()});
                },
                aoColumns : [
                    {
                        bSortable: false,
                        mData : "kid",
                        sWidth : "38px",
                        sClass : "center",
                        sTitle : '<label title="全选|不选"><input type="checkbox" class="ace" /><span class="lbl"></span></label>'
                    },
                    {
                        mData : "role_name",
                        sTitle : "角色名称"
                    },
                    {
                        mData : "role_flag",
                        sClass : "hidden-480",
                        sTitle : "权限标识"
                    },
                    {
                        mData : "utotal",
                        sTitle : "分配数",
                        sClass : "hidden-480",
                        sWidth : "10%",
                        render : function(value,type,row,meta){
                            if(value){
                                return value;
                            }else{
                                return 0;
                            }
                        }
                    },
                    {
                        mData : "mtotal",
                        sTitle : "菜单数",
                        sClass : "hidden-480",
                        sWidth : "10%",
                        render : function(value,type,row,meta){
                            if(value){
                                return value;
                            }else{
                                return 0;
                            }
                        }
                    },
                    {
                        mData : "_kid_",
                        sTitle : "<label style='color:#000;'>操作选项</label>",
                        bSortable : false,
                        sWidth : "40%"
                    }
                ],
                columnDefs : [
                    {
                        targets : 0,//指定的列
                        render : function(value,type,row,meta){//第1个参数可能会没有值!!!,当key不存在时就没有值
                            return '<label><input type="checkbox" name="kid" value="'+value+'" style="cursor:pointer;text-decoration:none;outline:none;"/><span class="lbl"></span></label>';
                        }
                    },
                    {
                        targets : -1,
                        render : function(value,type,row,meta){
                            var login = '${login_user}';
                            var roleFlag = row.role_flag;
                            if(roleFlag == 'administrators'){
                                var html = '';//上线后要删除
                                <shiro:hasPermission name="role_row_edit">
                                html += "<a href='javascript:thisPage.unAuth();' style='outline:none;text-decoration: none;color:#3b8cff;margin-left:6px;'>编辑</a>";
                                </shiro:hasPermission>
                                <shiro:hasPermission name="role_row_delById">
                                html += "<a class='hidden-xs' href='javascript:thisPage.unAuth();' style='outline:none;text-decoration: none;color:#f00;margin-left:6px;'>删除</a>";
                                </shiro:hasPermission>
                                <shiro:hasPermission name="role_row_delEmptyMenu">
                                html += "<a href='javascript:thisPage.unAuth();' style='outline:none;text-decoration: none;color:#1d953f;margin-left:6px;'>清空菜单</a>";
                                </shiro:hasPermission>
                                <shiro:hasPermission name="role_row_getRoleMenu">
                                <shiro:hasPermission name="role_row_saveRoleMenu">
                                html += "<a href='javascript:thisPage.unAuth();' style='outline:none;text-decoration: none;color:#008792;margin-left:6px;'>角色菜单</a>";
                                </shiro:hasPermission>
                                </shiro:hasPermission>
                                <shiro:hasRole name="administrators">
                                html = "<a href='javascript:thisPage.rowEdit("+meta.row+");' style='outline:none;text-decoration: none;color:#3b8cff;margin-left:6px;'>编辑</a>"+
                                "<a class='hidden-xs' href='javascript:thisPage.rowDel("+meta.row+");' style='outline:none;text-decoration: none;color:#f00;margin-left:6px;'>删除</a>"+
                                "<a href='javascript:thisPage.rowEmptyMenu("+meta.row+");' style='outline:none;text-decoration: none;color:#1d953f;margin-left:6px;'>清空菜单</a>"+
                                "<a href='javascript:thisPage.rowRoleMenu("+meta.row+");' style='outline:none;text-decoration: none;color:#008792;margin-left:6px;'>角色菜单</a>";
                                </shiro:hasRole>
                                return html;
                            }else{
                                var html = '';
                                <shiro:hasPermission name="role_row_edit">
                                html += "<a href='javascript:thisPage.rowEdit("+meta.row+");' style='outline:none;text-decoration: none;color:#3b8cff;margin-left:6px;'>编辑</a>";
                                </shiro:hasPermission>
                                <shiro:hasPermission name="role_row_delById">
                                html += "<a class='hidden-xs' href='javascript:thisPage.rowDel("+meta.row+");' style='outline:none;text-decoration: none;color:#f00;margin-left:6px;'>删除</a>";
                                </shiro:hasPermission>
                                <shiro:hasPermission name="role_row_delEmptyMenu">
                                html += "<a href='javascript:thisPage.rowEmptyMenu("+meta.row+");' style='outline:none;text-decoration: none;color:#1d953f;margin-left:6px;'>清空菜单</a>";
                                </shiro:hasPermission>
                                <shiro:hasPermission name="role_row_getRoleMenu">
                                <shiro:hasPermission name="role_row_saveRoleMenu">
                                html += "<a href='javascript:thisPage.rowRoleMenu("+meta.row+");' style='outline:none;text-decoration: none;color:#008792;margin-left:6px;'>角色菜单</a>";
                                </shiro:hasPermission>
                                </shiro:hasPermission>
                                return html;
                            }
                        }
                    },
                    {
                        targets: [1,2,3,4],
                        render: function (value,type,row,meta){
                            return pageDataTable.formatColumn(value);
                        }
                    }
                ]
            });
            pageDataTable.buttons(thisTable);
            pageDataTable.action(thisTable);
            pageDataTable.select(thisTable,tableDom);
            pageDataTable.tooltip();
            var thisJquery = $(tableDom).dataTable();
            var domRoleMenu = 'treeRoleMenu';
            var tree_obj_own = null;//变量标识,用于初始化及取消选中操作及获取已选中节点数据
            var settingOwn = {
                view: {
                    expandSpeed : 100,
                    showLine : true,
                    showIcon : true,
                    fontCss : {"color":"#000","outline":"none","text-decoration":"none"}
                },
                check: {
                    enable: true,
                    chkStyle: "checkbox",
                    chkboxType: {"Y":"p","N":"s"}
                },
                data: {
                    simpleData: {
                        enable: true,
                        idKey: "kid",
                        pIdKey: "pid",
                    }
                },
                callback : {
                    beforeClick : function(treeId,node,clickFlag){
                        return false;
                    }
                }
            };
            thisPage = {
                init : function(){
                    this.addEvent();
                },
                addEvent : function(){
                    this.btnEvent();
                },
                btnEvent : function(){
                    <shiro:hasPermission name="role_row_edit">
                    $(tableDom +' tbody').on('dblclick','tr',function(){
                        thisPage.trDblclick(thisTable.row(this).data());
                    });</shiro:hasPermission>
                    <shiro:hasPermission name="role_btn_add">
                    $('#btnAdd').on('click',function(){
                        thisPage.edit();
                    });</shiro:hasPermission>
                    <shiro:hasPermission name="role_btn_listData">
                    /*普通搜索按钮*/
                    $('#btnSearch').on('click',function(){
                        thisPage.search();
                    });
                    /*按钮组-自定义显示列*/
                    $('#iconColumn').on('click',function(){
                        pageDataTable.columnCustom(thisTable,tableDom,'#divKeyColumns');
                    });
                    /*按钮组-搜索*/
                    $('#iconRefresh').on('click',function(){
                        thisPage.search();
                    });</shiro:hasPermission>
                    <shiro:hasPermission name="role_btn_delByKeys">
                    $('#btnDel').on('click',function(){
                        thisPage.delKeys();
                    });</shiro:hasPermission>
                },
                <shiro:hasPermission name="role_btn_delByKeys">
                /*批量删除*/
                delKeys : function(){
                    var kids = '';
                    var index = 0;
                    $(tableDom + ' tbody input:checked').each(function(){
                        index ++;
                        var value = this.value;
                        if(value != null && value != ''){
                            if(kids.length > 0)
                                kids += ",";
                            kids += value;
                        }
                    });
                    if(kids == ''){
                        layerFn.alert('请选择要删除的角色',AppKey.code.code199);
                        return;
                    }
                    var _bl_ = false;//上线后要删除
                    var array = new Array();
                    array = thisTable.rows({selected : true}).data().toArray();
                    var _flag_ = '';
                    for(var i = 0; i < array.length; i++){
                        var _role_flag = array[i].role_flag;
                        if(_role_flag == 'admin' || _role_flag == 'administrators'){
                            _flag_ = _role_flag;
                            _bl_ = true;
                        }
                    }
                    if(_bl_){//上线后要删除
                        layerFn.alert('不要对标识'+_flag_+'操作',AppKey.code.code199);
                        return;
                    }
                    layerFn.confirm('将要准备删除['+index+']个角色且是无法恢复,确定要继续吗?',function(){
                        layerFn.delBatchHint(urlDelByKeys,kids,function(data){
                            thisPage.complete(data,null,true);
                        });
                    });
                },</shiro:hasPermission>
                unAuth : function(){
                    layerFn.alert('无权限操作',AppKey.code.code199);
                },
                <shiro:hasPermission name="role_row_edit">
                trDblclick : function(data){
                    thisPage.edit(data.kid,data.role_name,data.role_flag);
                },</shiro:hasPermission>
                <shiro:hasPermission name="role_btn_listData">
                search : function(){
                    $(tableDom + ' input[type=checkbox]').prop('checked',false);
                    thisTable.draw();
                },</shiro:hasPermission>
                resetFormRole : function(){
                    winFn.clearFormData('#form_role_edit');
                },
                edit : function(kid,role_name,role_flag){
                    var title = '添加角色';
                    if(kid != null && kid.length >0){
                        title = '编辑角色';
                        <shiro:hasPermission name="role_row_edit">
                        winFn.setDomValue('#input_role_edit_keyId',kid);
                        thisPage.openDialog(title,kid);
                        </shiro:hasPermission>
                    }else{
                        winFn.setDomValue('#input_role_edit_keyId','');
                        <shiro:hasPermission name="role_btn_add">
                        thisPage.openDialog(title,null);
                        </shiro:hasPermission>
                    }
                    thisPage.resetFormRole();
                    if(kid != null){
                        winFn.setDomValue('#role_name',role_name);
                        winFn.setDomValue('#role_flag',role_flag);
                    }
                },
                openDialog : function(title,kid){
                    layerFn.addOrEdit(title,'#div_role_edit',['340px','200px'],function(index,layero){
                        if (verifyFn.inputRequired('#role_name')){
                            layerFn.alert('请输入角色名称',AppKey.code.code199);
                            return;
                        }
                        if (verifyFn.inputRequired('#role_flag')){
                            layerFn.alert('角色标识不能为空',AppKey.code.code199);
                            return;
                        }
                        var params = {
                            role_name : winFn.getDomValue('#role_name'),
                            role_flag : winFn.getDomValue('#role_flag'),
                            kid : winFn.getDomValue('#input_role_edit_keyId')
                        };
                        thisPage.commit(kid,index,params);
                    });
                },
                <shiro:hasPermission name="role_row_edit">
                rowEdit : function(index){
                    var data = thisJquery.fnGetData(index);
                    thisPage.edit(data.kid,data.role_name,data.role_flag);
                },</shiro:hasPermission>
                <shiro:hasPermission name="role_row_delById">
                rowDel : function(index){
                    var row = thisJquery.fnGetData(index);
                    var _role_flag_ = row.role_flag;//上线后要删除
                    if(_role_flag_ =='admin'){
                        layerFn.alert('不要删除标识为admin',AppKey.code.code199);
                        return;
                    }
                    if(_role_flag_ =='administrators'){
                        layerFn.alert('不要删除标识为administrators',AppKey.code.code199);
                        return;
                    }
                    layerFn.confirm('['+row.role_name+']删除后是无法恢复,确定要删除吗?',function(){
                        layerFn.delByIdHint(urlDelById,row.kid,function(data){
                            thisPage.complete(data,null,true);
                        });
                    });
                },</shiro:hasPermission>
                <shiro:hasPermission name="role_row_delEmptyMenu">
                /*清空菜单*/
                rowEmptyMenu : function(index){
                    var row = thisJquery.fnGetData(index);
                    var total = row.mtotal;
                    if(total == null){
                        layerFn.alert('['+row.role_name+']还没有分配菜单',AppKey.code.code199);
                        return;
                    }
                    layerFn.confirm('你确定要清空<span style="color:#1e9fff">'+row.role_name+'</span>的菜单操作吗?',function(){
                        layerFn.submit(urlDelEmptyMenu,{kid:row.kid},function(data){
                            thisPage.complete(data,null,true);
                        });
                    });
                },</shiro:hasPermission>
                <shiro:hasPermission name="role_row_getRoleMenu">
                /*角色菜单*/
                rowRoleMenu : function(index){
                    var row = thisJquery.fnGetData(index);
                    layerFn.queryGetHint(urlGetRoleMenu,{roleId:row.kid},function(data){
                        tree_obj_own = $.fn.zTree.init($("#"+domRoleMenu),settingOwn,data.data);
                        tree_obj_own.expandAll(true);
                        layerFn.addOrEdit('角色['+row.role_name+']菜单数据','#div_role_menu',['420px','420px'],function(index){
                            var nodes = tree_obj_own.getCheckedNodes(true);
                            var kids = '';
                            $.each(nodes,function(index,data){
                                var value = data.kid;
                                if(value != null && value != ''){
                                    if(kids.length > 0)
                                        kids += ",";
                                    kids += value;
                                }
                            });
                            <shiro:hasPermission name="role_row_saveRoleMenu">
                            layerFn.submit(urlSaveRoleMenu,{kids:kids,roleId:row.kid},function(data){
                                thisPage.complete(data,index,true);
                            });
                            </shiro:hasPermission>
                        },'全选',function(){
                            checkOption = !checkOption;
                            if(checkOption){
                                $('a.layui-layer-btn2').text('不选');
                                tree_obj_own.checkAllNodes(true);
                            }else{
                                $('a.layui-layer-btn2').text('全选');
                                tree_obj_own.checkAllNodes(false);
                            }
                        });
                    });
                },</shiro:hasPermission>
                commit : function(kid,index,params){
                    var url = notAuthorized;
                    <shiro:hasPermission name="role_btn_add">
                    url = urlAdd;
                    </shiro:hasPermission>
                    if (kid != null && kid != ''){
                        <shiro:hasPermission name="role_row_edit">
                        url = urlEdit;
                        </shiro:hasPermission>
                    }
                    layerFn.submit(url,params,function(data){
                        thisPage.complete(data,index,true);
                    });
                },
                complete : function(data,index,search){
                    try{
                        if(index){
                            layerFn.closeIndex(index);
                        }
                        if(search){
                            thisPage.search();
                        }
                        if(data){
                            layerFn.handleResult(data.msg,data.code);
                        }
                    }catch(e){}
                }
            };
            thisPage.init();
            </shiro:hasPermission>
        });
    });
</script>