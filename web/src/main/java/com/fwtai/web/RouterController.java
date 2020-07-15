package com.fwtai.web;

import com.fwtai.config.ConfigFile;
import com.fwtai.service.core.MenuService;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

/**
 * 页面跳转|路由器,方法上或类上不能还有final关键字
 * @作者 田应平
 * @版本 v1.0
 * @创建时间 2020-02-28 1:46
 * @QQ号码 444141300
 * @Email service@yinlz.com
 * @官网 <url>http://www.yinlz.com</url>
*/
@Controller
public class RouterController{

    @Resource
    private MenuService menuService;

    @RequiresPermissions("page_main")
    @GetMapping(value = "main",name = "page_main")
    public ModelAndView main(final HttpServletRequest request){
        final ModelAndView modeView = new ModelAndView();
        final String userId = (String) request.getSession().getAttribute(ConfigFile.LOGIN_KEY);
        final String data = menuService.getMenuData(userId);
        modeView.addObject("menuData",data);
        modeView.setViewName("main");
        return modeView;
    }

    @RequiresPermissions("page_sys_menu")
    @GetMapping(value = "sys_menu",name = "page_sys_menu")
    public String sysMenu(){
        return "sys_menu";
    }

    @RequiresPermissions("page_sys_user")
    @GetMapping(value = "sys_user",name = "page_sys_user")
    public String sysUser(){
        return "sys_user";
    }

    @RequiresPermissions("page_sys_role")
    @GetMapping(value = "sys_role",name = "page_sys_role")
    public String sysRole(){
        return "sys_role";
    }
}