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
                            <shiro:hasPermission name="user_btn_listData">
                            <td>
                                登录账号
                            </td>
                            <td style="padding: 0px 0px 0px 6px;">
                                <div class="input-group">
                                    <input type="text" id="key_user_name" class="form-control search-query" placeholder="登录账号关键字" />
                                    <shiro:hasPermission name="user_getList">
                                        <%--页面显示控制及js控制--%>
                                    </shiro:hasPermission>
                                    <span class="input-group-btn">
                                        <button type="button" class="btn btn-inverse btn-white" id="btnSearch">
                                            <span class="ace-icon fa fa-search bigger-110"></span>
                                            搜索
                                        </button>
                                    </span>
                                </div>
                            </td>
                            </shiro:hasPermission>
                            <shiro:hasPermission name="user_btn_add">
                            <td>
                                <div class="input-group">
                                <span class="input-group-btn">
                                    <button type="button" class="btn btn-inverse btn-white" id="btnAdd">
                                        <span class="fa fa-user-plus bigger-110"></span>
                                        添加
                                    </button>
                                </span>
                                </div>
                            </td>
                            </shiro:hasPermission>
                            <shiro:hasPermission name="user_btn_delByKeys">
                            <td class="hidden-480">
                                <div class="input-group">
                                <span class="input-group-btn">
                                    <button type="button" class="btn btn-inverse btn-white" id="btnDel">
                                        <span class="fa fa-user-times red2 bigger-110"></span>
                                        删除
                                    </button>
                                </span>
                                </div>
                            </td>
                            </shiro:hasPermission>
                            <shiro:hasPermission name="user_btn_row_getAllotRole">
                            <shiro:hasPermission name="user_btn_row_saveAllotRole">
                            <td class="hidden-480">
                                <div class="input-group">
                                <span class="input-group-btn">
                                    <button type="button" class="btn btn-inverse btn-white" id="btnAllotRole">
                                        <span class="fa fa-link green bigger-110"></span>
                                        角色
                                    </button>
                                </span>
                                </div>
                            </td>
                            </shiro:hasPermission>
                            </shiro:hasPermission>
                        </tr>
                    </table>
                    <shiro:hasPermission name="user_btn_listData">
                    <div class="hidden-480 pull-right tableTools-container"></div>
                    </shiro:hasPermission>
                </div>
                <shiro:hasPermission name="user_btn_listData">
                <table id="tableListUser" class="table table-striped table-bordered table-hover"></table>
                </shiro:hasPermission>
            </div>
        </div>
        <!-- PAGE CONTENT ENDS -->
    </div>
</div>
<div id="div_user_edit" style="display:none;padding:20px 0px;">
    <form class="form-horizontal" id="form_user_edit" role="form">
        <label class="col-sm-3 control-label no-padding-right" for="user_name"><div class="hr-1"></div>登录账号</label>
        <div class="col-sm-7">
            <input type="text" id="user_name" placeholder="登录账号" class="form-control"/>
        </div>
        <label class="col-sm-3 control-label no-padding-right" for="user_password"><div class="hr-4"></div>账号密码</label>
        <div class="col-sm-7"><div class="hr-4"></div><%--input--%>
            <input type="password" id="user_password" placeholder="账号密码" class="form-control" />
        </div>
        <label class="col-sm-3 control-label no-padding-right" for="verify_password"><div class="hr-4"></div>确认密码</label>
        <div class="col-sm-7"><div class="hr-4"></div>
            <input type="password" id="verify_password" placeholder="确认密码" class="form-control"/>
        </div>
    </form>
</div>
<div id="div_role_data" style="display:none;padding:2px 0px;"></div>
<div id="divKeyColumns" style="display:none;padding:1px 0px;"></div>
<div id="div_own_menu" style="display:none;padding:2px 2px 2px 0px">
    <form class="form-horizontal">
        <div class="col-sm-12">
            <ul id="treeOwnMenu" class="ztree"></ul>
        </div>
    </form>
</div>
<input type="hidden" id="input_user_edit_keyId"/><%--编辑时用的id--%>
<script type="text/javascript">
    var scripts = [null,null];
    $('.page-content-area').ace_ajax('loadScripts',scripts,function(){
        var tableDom = '#tableListUser';
        var checkOption = 1;
        $(function(){
            <shiro:hasPermission name="user_btn_listData">
            var urlRoute = '/user/';/*请求controller层的url*/
            var notAuthorized = urlRoute + "notAuthorized";
            var getList = urlRoute + 'listData';/*获取菜单列表,此处不需要添加的,已在请求的url添加了前缀*/
            <shiro:hasPermission name="user_btn_add">
            var urlAdd = urlRoute + 'add';/*添加*/
            </shiro:hasPermission>
            <shiro:hasPermission name="user_row_edit">
            var urlEdit = urlRoute + 'edit';/*编辑*/
            </shiro:hasPermission>
            <shiro:hasPermission name="user_row_delById">
            var urlDelById = urlRoute + 'delById';/*根据id删除对应的数据*/
            </shiro:hasPermission>
            <shiro:hasPermission name="user_btn_delByKeys">
            var urlDelByKeys = urlRoute + 'delByKeys';/*批量删除*/
            </shiro:hasPermission>
            <shiro:hasPermission name="user_btn_row_getAllotRole">
            var urlGetAllotRole = urlRoute + 'getAllotRole';/*获取角色信息*/
            </shiro:hasPermission>
            <shiro:hasPermission name="user_btn_row_saveAllotRole">
            var urlSaveAllotRole = urlRoute + 'saveAllotRole';/*保存分配角色*/
            </shiro:hasPermission>
            <shiro:hasPermission name="user_row_editEnabled">
            var urlEditEnabled = urlRoute + 'editEnabled';/*控制启禁用*/
            </shiro:hasPermission>
            <shiro:hasPermission name="user_row_getOwnMenu">
            var urlGetOwnMenu = urlRoute + 'getOwnMenu';/*根据指定userid获取菜单用于分配私有菜单*/
            </shiro:hasPermission>
            <shiro:hasPermission name="user_row_saveOwnMenu">
            var urlSaveOwnMenu = urlRoute + 'saveOwnMenu';/*保存私有菜单(用户菜单)*/
            </shiro:hasPermission>
            <shiro:hasPermission name="user_row_getMenuData">
            var urlGetMenuData = urlRoute + 'getMenuData';/*查看指定userid所有权限菜单数据*/
            </shiro:hasPermission>
            var thisTable = pageDataTable.initDataTable({
                tableDom : tableDom,
                sAjaxSource: getList,
                fnServerParams : function(params){
                    params.push({"name":"user_name","value":$("#key_user_name").val()});
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
                        mData : "user_name",
                        sTitle : "登录账号",
                    },
                    {
                        mData : "enabled",
                        sTitle : "账号状态",
                        sClass : "hidden-480",
                        sWidth : "10%",
                        render : function(value,type,row,meta){
                            if(value === 0){
                                if(row.error_count >= 3){
                                    return '锁定(<span style="color:#f00">'+row.error_count+'</span>)';
                                }
                                return '正常';
                            }else if(value === 1){
                                return '禁用';
                            }else{
                                return "";
                            }
                        }
                    },
                    {
                        mData : "add_date",
                        sTitle : "添加时间",
                        sClass : "hidden-480",
                        sWidth : "11%"
                    },
                    {
                        mData : "logintime",
                        sTitle : "最近登录",
                        sClass : "hidden-480",
                        sWidth : "12%"
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
                            var userName = row.user_name;
                            if(userName == 'admin'){//上线后要删除
                                var html = "";
                                <shiro:hasPermission name="user_row_edit">
                                html += "<a href='javascript:thisPage.unAuth();' style='outline:none;text-decoration: none;color:#3b8cff;margin-left:6px;'>编辑</a>";
                                </shiro:hasPermission>
                                <shiro:hasPermission name="user_row_delById">
                                html += "<a href='javascript:thisPage.unAuth();' style='outline:none;text-decoration: none;color:#f00;margin-left:6px;'>删除</a>";
                                </shiro:hasPermission>
                                <shiro:hasPermission name="user_btn_row_getAllotRole">
                                <shiro:hasPermission name="user_btn_row_saveAllotRole">
                                html += "<a class='hidden-xs' href='javascript:thisPage.unAuth();' style='outline:none;text-decoration: none;color:#00a6ac;margin-left:6px;'>角色</a>";
                                </shiro:hasPermission>
                                </shiro:hasPermission>
                                <shiro:hasPermission name="user_row_editEnabled">
                                html += "<a href='javascript:thisPage.unAuth();' style='outline:none;text-decoration: none;color:#33a3dc;margin-left:6px;'>"+(row.enabled === 0 ? "禁用":"启用")+"</a>";
                                </shiro:hasPermission>
                                <shiro:hasPermission name="user_row_getOwnMenu">
                                <shiro:hasPermission name="user_row_saveOwnMenu">
                                html += "<a class='hidden-xs' href='javascript:thisPage.unAuth();' style='outline:none;text-decoration: none;color:#008792;margin-left:6px;'>私有菜单</a>";
                                </shiro:hasPermission>
                                </shiro:hasPermission>
                                <shiro:hasPermission name="user_row_getMenuData">
                                html += "<a href='javascript:thisPage.unAuth();' style='outline:none;text-decoration: none;color:#06aff3;margin-left:6px;'>权限菜单</a>";
                                </shiro:hasPermission>
                                <shiro:hasRole name="administrators">
                                html = "<a href='javascript:thisPage.rowEdit("+meta.row+");' style='outline:none;text-decoration: none;color:#3b8cff;margin-left:6px;'>编辑</a>" +
                                "<a href='javascript:javascript:thisPage.unAuth();' style='outline:none;text-decoration: none;color:#f00;margin-left:6px;'>删除</a>" +
                                "<a class='hidden-xs' href='javascript:thisPage.rowAllotRole("+meta.row+");' style='outline:none;text-decoration: none;color:#00a6ac;margin-left:6px;'>角色</a>"+
                                "<a href='javascript:javascript:layerFn.alert(\"禁止操作,否则不能维护系统\",AppKey.code.code199);' style='outline:none;text-decoration: none;color:#33a3dc;margin-left:6px;'>"+(row.enabled === 0 ? "禁用":"启用")+"</a>"+
                                "<a class='hidden-xs' href='javascript:layerFn.alert(\"嗨,你个土匪禁止操作!\",AppKey.code.code199);' style='outline:none;text-decoration: none;color:#008792;margin-left:6px;'>私有菜单</a>"+
                                "<a href='javascript:thisPage.rowOwnMenu("+meta.row+");' style='outline:none;text-decoration: none;color:#06aff3;margin-left:6px;'>权限菜单</a>";
                                </shiro:hasRole>
                                return html;
                            }else{
                                var html = "";
                                <shiro:hasPermission name="user_row_edit">
                                html += "<a href='javascript:thisPage.rowEdit("+meta.row+");' style='outline:none;text-decoration: none;color:#3b8cff;margin-left:6px;'>编辑</a>";
                                </shiro:hasPermission>
                                <shiro:hasPermission name="user_row_delById">
                                html += "<a href='javascript:thisPage.rowDel("+meta.row+");' style='outline:none;text-decoration: none;color:#f00;margin-left:6px;'>删除</a>";
                                </shiro:hasPermission>
                                <shiro:hasPermission name="user_btn_row_getAllotRole">
                                <shiro:hasPermission name="user_btn_row_saveAllotRole">
                                html += "<a class='hidden-xs' href='javascript:thisPage.rowAllotRole("+meta.row+");' style='outline:none;text-decoration: none;color:#00a6ac;margin-left:6px;'>角色</a>";
                                </shiro:hasPermission>
                                </shiro:hasPermission>
                                <shiro:hasPermission name="user_row_editEnabled">
                                html += "<a href='javascript:thisPage.rowDisable("+meta.row+");' style='outline:none;text-decoration: none;color:#33a3dc;margin-left:6px;'>"+(row.enabled === 0 ? "禁用":"启用")+"</a>";
                                </shiro:hasPermission>
                                <shiro:hasPermission name="user_row_getOwnMenu">
                                <shiro:hasPermission name="user_row_saveOwnMenu">
                                html += "<a class='hidden-xs' href='javascript:thisPage.rowUserMenu("+meta.row+");' style='outline:none;text-decoration: none;color:#008792;margin-left:6px;'>私有菜单</a>";
                                </shiro:hasPermission>
                                </shiro:hasPermission>
                                <shiro:hasPermission name="user_row_getMenuData">
                                html += "<a href='javascript:thisPage.rowOwnMenu("+meta.row+");' style='outline:none;text-decoration: none;color:#06aff3;margin-left:6px;'>权限菜单</a>";
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
            var domOwnMenu = 'treeOwnMenu';
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
            var setting = {
                view : {
                    expandSpeed : 100,
                    showLine : true,
                    showIcon : true,
                    fontCss : {"color":"#000","outline":"none","text-decoration":"none"}
                },
                data: {
                    simpleData: {
                        enable: true,
                        idKey: "kid",
                        pIdKey: "pid"
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
                    <shiro:hasPermission name="user_row_edit">
                    $(tableDom +' tbody').on('dblclick','tr',function(){
                        thisPage.trDblclick(thisTable.row(this).data());
                    });</shiro:hasPermission>
                    <shiro:hasPermission name="user_btn_add">
                    $('#btnAdd').on('click',function(){
                        thisPage.edit();
                    });</shiro:hasPermission>
                    <shiro:hasPermission name="user_btn_listData">
                    /*搜索按钮*/
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
                    <shiro:hasPermission name="user_btn_delByKeys">
                    $('#btnDel').on('click',function(){
                        thisPage.delKeys();
                    });</shiro:hasPermission>
                    <shiro:hasPermission name="user_btn_row_getAllotRole">
                    <shiro:hasPermission name="user_btn_row_saveAllotRole">
                    $('#btnAllotRole').on('click',function(){
                        var kids = '';
                        $(tableDom + ' tbody input:checked').each(function(){
                            var value = this.value;
                            if(value != null && value != ''){
                                if(kids.length > 0)
                                    kids += ",";
                                kids += value;
                            }
                        });
                        if(kids == ''){
                            layerFn.alert('请选择要分配角色的账号',AppKey.code.code199);
                            return;
                        }
                        var _bl_ = false;//上线后要删除
                        var array = new Array();
                        array = thisTable.rows({selected : true}).data().toArray();
                        for(var i = 0; i < array.length; i++){
                            if(array[i].user_name == 'admin'){
                                _bl_ = true;
                            }
                        }
                        if(_bl_){//上线后要删除
                            layerFn.alert('不要对admin操作',AppKey.code.code199);
                            return;
                        }
                        thisPage.allotRole(null,null,kids);
                    });</shiro:hasPermission>
                    </shiro:hasPermission>
                },
                <shiro:hasPermission name="user_btn_row_getAllotRole">
                allotRole : function(userId,user_name,userIds){
                    layerFn.queryGetHint(urlGetAllotRole,{userId:userId},function(data){
                        roleData(data.data);
                        var title = '分配角色';
                        if(user_name != null){
                            title = '为['+user_name+']分配角色';
                        }
                        layerFn.addOrEdit(title,'#div_role_data',['500px','430px'],function(index,layero){
                            var kids = '';
                            $("#div_role_data"+" input[name='roles']:checked").each(function(){
                                var value = this.value;
                                if(value != null && value != ''){
                                    if(kids.length > 0)
                                        kids += ",";
                                    kids += value;
                                }
                            });
                            var params = userIds == null ? {kids:kids,type:1,userId:userId} : {kids:kids,type:2,userIds:userIds};
                            <shiro:hasPermission name="user_btn_row_saveAllotRole">
                            layerFn.submit(urlSaveAllotRole,params,function(data){
                                thisPage.complete(data,index,true);
                            });
                            </shiro:hasPermission>
                        });
                    });
                },</shiro:hasPermission>
                <shiro:hasPermission name="user_btn_delByKeys">
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
                        layerFn.alert('请选择要删除的账号',AppKey.code.code199);
                        return;
                    }
                    var _bl_ = false;
                    var array = new Array();
                    array = thisTable.rows({selected : true}).data().toArray();
                    for(var i = 0; i < array.length; i++){
                        if(array[i].user_name == 'admin'){
                            _bl_ = true;
                        }
                    }
                    if(_bl_){//上线后要删除
                        layerFn.alert('不要对admin操作',AppKey.code.code199);
                        return;
                    }
                    layerFn.confirm('将要准备删除['+index+']个账号且是无法恢复,确定要继续吗?',function(){
                        layerFn.delBatchHint(urlDelByKeys,kids,function(data){
                            thisPage.complete(data,null,true);
                        });
                    });
                },</shiro:hasPermission>
                unAuth : function(){
                    layerFn.alert('无权限操作',AppKey.code.code199);
                },
                <shiro:hasPermission name="user_row_edit">
                trDblclick : function(data){
                    thisPage.edit(data.kid,data.user_name);
                },</shiro:hasPermission>
                <shiro:hasPermission name="user_btn_listData">
                search : function(){
                    $(tableDom + ' input[type=checkbox]').prop('checked',false);
                    thisTable.draw();
                },</shiro:hasPermission>
                resetFormUser : function(){
                    winFn.clearFormData('#form_user_edit');
                },
                edit : function(kid,user_name){
                    var title = '添加账号';
                    if(kid != null && kid.length >0){
                        title = '编辑账号';
                        <shiro:hasPermission name="user_row_edit">
                        winFn.setDomValue('#input_user_edit_keyId',kid);
                        thisPage.openDialog(title,kid,user_name);
                        </shiro:hasPermission>
                    }else{
                        winFn.setDomValue('#input_user_edit_keyId','');
                        <shiro:hasPermission name="user_btn_add">
                        thisPage.openDialog(title,null,null);
                        </shiro:hasPermission>
                    }
                },
                openDialog : function(title,kid,user_name){
                    layerFn.addOrEdit(title,'#div_user_edit',['410px','240px'],function(index,layero){
                        if (verifyFn.inputRequired('#user_name')){
                            layerFn.alert('请输入登录账号',AppKey.code.code199);
                            return;
                        }
                        if (verifyFn.inputRequired('#user_password')){
                            layerFn.alert('请输入账号密码',AppKey.code.code199);
                            return;
                        }
                        if (verifyFn.inputRequired('#verify_password')){
                            layerFn.alert('请输入确认密码',AppKey.code.code199);
                            return;
                        }
                        var password = winFn.getDomValue('#user_password');
                        var verify = winFn.getDomValue('#verify_password');
                        var bl = verifyFn.checkEqual(password,verify);
                        if(bl){
                            layerFn.alert('你输入的两次密码不一致',AppKey.code.code199);
                            return;
                        }
                        var params = {
                            user_name : winFn.getDomValue('#user_name'),
                            user_password : winFn.getDomValue('#user_password'),
                            verify_password : winFn.getDomValue('#verify_password'),
                            kid : winFn.getDomValue('#input_user_edit_keyId')
                        };
                        thisPage.commit(kid,index,params);
                    });
                    thisPage.resetFormUser();
                    if(kid != null){
                        <shiro:hasPermission name="user_row_edit">
                        $('#user_name').val(user_name);
                        $("#user_name").attr("onfocus", "this.blur()");
                        $("#user_name").css({"background":"#ccc"},{"cursor":"not-allowed"});
                        </shiro:hasPermission>
                    }else{
                        <shiro:hasPermission name="user_btn_add">
                        $("#user_name").attr("onfocus", "");
                        $("#user_name").css({"background":""},{"cursor":""});
                        </shiro:hasPermission>
                    }
                },
                <shiro:hasPermission name="user_row_edit">
                rowEdit : function(index){
                    var data = thisJquery.fnGetData(index);
                    thisPage.edit(data.kid,data.user_name);
                },</shiro:hasPermission>
                <shiro:hasPermission name="user_row_delById">
                rowDel : function(index){
                    var row = thisJquery.fnGetData(index);
                    var user_name = row.user_name;
                    if(user_name == 'admin'){
                        layerFn.alert('不能操作['+user_name+']账号',AppKey.code.code199);
                        return;
                    }
                    layerFn.confirm('['+row.user_name+']删除后是无法恢复,确定要删除吗?',function(){
                        layerFn.delByIdHint(urlDelById,row.kid,function(data){
                            thisPage.complete(data,null,true);
                        });
                    });
                },</shiro:hasPermission>
                <shiro:hasPermission name="user_btn_row_getAllotRole">
                /*分配角色*/
                rowAllotRole : function(index){
                    var row = thisJquery.fnGetData(index);
                    thisPage.allotRole(row.kid,row.user_name,null);
                },</shiro:hasPermission>
                <shiro:hasPermission name="user_row_editEnabled">
                /*启用禁用*/
                rowDisable : function(index){
                    var row = thisJquery.fnGetData(index);
                    var user_name = row.user_name;
                    if(user_name == 'admin'){
                        layerFn.alert('不能操作['+user_name+']账号',AppKey.code.code199);
                        return;
                    }
                    var enabled = row.enabled;
                    var msg = '禁用';
                    var disable = 1;
                    if(enabled == 1){
                        msg = '启用';
                        disable = 0;
                    }
                    layerFn.confirm('你确定要'+msg+'<span style="color:#1e9fff">'+row.user_name+'</span>操作吗?',function(){
                        layerFn.submit(urlEditEnabled,{enabled:row.enabled,userId:row.kid,disable:disable},function(data){
                            thisPage.complete(data,null,true);
                        });
                    });
                },</shiro:hasPermission>
                <shiro:hasPermission name="user_row_getOwnMenu">
                /*私有菜单(用户菜单)*/
                rowUserMenu : function(index){
                    checkOption = 1;
                    var row = thisJquery.fnGetData(index);
                    layerFn.queryGetHint(urlGetOwnMenu,{userId:row.kid},function(data){
                        tree_obj_own = $.fn.zTree.init($("#"+domOwnMenu),settingOwn,data.data);
                        tree_obj_own.expandAll(true);
                        layerFn.addOrEdit('账号['+row.user_name+']私有菜单','#div_own_menu',['420px','420px'],function(index){
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
                            <shiro:hasPermission name="user_row_saveOwnMenu">
                            layerFn.submit(urlSaveOwnMenu,{kids:kids,userId:row.kid},function(data){
                                layerFn.closeIndex(index);
                                layerFn.handleResult(data.msg,data.code);
                            });
                            </shiro:hasPermission>
                        },'全选',function(){
                            checkOption++;
                            if(checkOption % 2 === 0){
                                $('a.layui-layer-btn2').text('不选');
                                tree_obj_own.checkAllNodes(true);
                            }else{
                                $('a.layui-layer-btn2').text('全选');
                                tree_obj_own.checkAllNodes(false);
                            }
                        });
                    });
                },</shiro:hasPermission>
                <shiro:hasPermission name="user_row_getMenuData">
                /*权限菜单*/
                rowOwnMenu : function(index){
                    var row = thisJquery.fnGetData(index);
                    layerFn.queryGetHint(urlGetMenuData,{userId:row.kid},function(data){
                        tree_obj_own = $.fn.zTree.init($("#"+domOwnMenu),setting,data.data);
                        tree_obj_own.expandAll(true);
                        layerFn.viewDialog('账号['+row.user_name+']所拥有的权限菜单','#div_own_menu',['420px','420px']);
                    });
                },</shiro:hasPermission>
                commit : function(kid,index,params){
                    var url = notAuthorized;
                    <shiro:hasPermission name="user_btn_add">
                    url = urlAdd;
                    </shiro:hasPermission>
                    if (kid != null && kid != ''){
                        <shiro:hasPermission name="user_row_edit">
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
            function roleData(data){
                var html = "<table class='table table-striped table-bordered table-hover no-margin-bottom no-border-top'>";
                html += "<thead>";
                html += "<tr>";
                html += "<th>角色名称</th>";
                html += "<th width='40' class='center'>";
                html += "<i class='fa fa-link green bigger-110'></i>";
                html += "</th>";
                html += "</tr>";
                html += "</thead>";
                html += "<tbody>";
                $.each(data,function(index,values){
                    html += "<tr>";
                    html += "<td>"+values.role_name+"</td>";
                    html += "<td class='center'>";
                    html += "<input type='checkbox' name='roles' value='"+values.kid+"' id='"+values.kid+"'/><label style='margin:0px;'></label>";
                    html += "</td>";
                    html += "</tr>";
                });
                html += "</tbody>";
                html += "</table>";
                $('#div_role_data').html(html);
                $.each(data,function(index,values){
                    var checked = values.checked;
                    if(checked != null && checked != ''){
                        $('#'+values.kid).prop("checked",true);
                    }
                });
                $('#div_role_data').hcheckbox();//注意dom渲染完成后才初始化,否则没有效果
            }
            </shiro:hasPermission>
        });
    });
</script>