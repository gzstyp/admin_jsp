/*
 Navicat Premium Data Transfer

 Source Server         : 118.187.4.175_xinrui
 Source Server Type    : MySQL
 Source Server Version : 80019
 Source Host           : 118.187.4.175:12587
 Source Schema         : admin_master

 Target Server Type    : MySQL
 Target Server Version : 80019
 File Encoding         : 65001

 Date: 24/06/2020 08:49:06
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for sys_auth_filter
-- ----------------------------
DROP TABLE IF EXISTS `sys_auth_filter`;
CREATE TABLE `sys_auth_filter`  (
  `kid` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '主键',
  `url` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'url地址(唯一)',
  `permission` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '过滤器类型(具备的权限)',
  `sort_order` smallint(0) UNSIGNED NOT NULL COMMENT '排序',
  `remark` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '备注',
  PRIMARY KEY (`kid`) USING BTREE,
  UNIQUE INDEX `index_url`(`url`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = 'shiro的过滤器' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_auth_filter
-- ----------------------------
INSERT INTO `sys_auth_filter` VALUES ('0000000025d379a2ffffffffb2a5104f', '/error', 'anon', 1, '错误页|未登录或未授权的跳转的url');
INSERT INTO `sys_auth_filter` VALUES ('111fffffbd911aa0ffffffffd5637fff', '/images/**', 'anon', 7, '图片');
INSERT INTO `sys_auth_filter` VALUES ('111fffffd3d10c7400000000696dc111', '/user/logout', 'anon', 8, '退出');
INSERT INTO `sys_auth_filter` VALUES ('111ffffff3b5807e000000003f2caf11', '/index', 'anon', 10, '默认跳转的页面');
INSERT INTO `sys_auth_filter` VALUES ('e1a2bf3d9cc646a1a328f4fe550f0aa9', '/avatars/**', 'anon', 11, NULL);
INSERT INTO `sys_auth_filter` VALUES ('fe79a625fa084472901cd44667eff503', '/fonts/**', 'anon', 12, NULL);
INSERT INTO `sys_auth_filter` VALUES ('ff91c54757ad4d018196b0abaccb90fd', '/img/**', 'anon', 13, NULL);
INSERT INTO `sys_auth_filter` VALUES ('fffff0003aa62b7b0000000079302bll', '/login', 'anon', 14, '登录页');
INSERT INTO `sys_auth_filter` VALUES ('ffffffff8c468a55ffffffff8f59d635', '/user/renewalToken', 'anon', 15, '更新令牌');
INSERT INTO `sys_auth_filter` VALUES ('ffffffffa73811e90000000040a506f9', '/user/login', 'anon', 2, '登录接口');
INSERT INTO `sys_auth_filter` VALUES ('ffffffffbd911aa0ffffffffd5637367', '/*.ico', 'anon', 3, '图标');
INSERT INTO `sys_auth_filter` VALUES ('ffffffffc5e3d2cbffffffffb6cb91d9', '/**.html', 'anon', 4, '静态页面');
INSERT INTO `sys_auth_filter` VALUES ('ffffffffc6bc47ec0000000075f2376b', '/css/**', 'anon', 5, 'css样式');
INSERT INTO `sys_auth_filter` VALUES ('ffffffffd3d10c7400000000696dcc08', '/js/**', 'anon', 6, 'js脚本');
INSERT INTO `sys_auth_filter` VALUES ('fffffffff3b5807e000000003f2ca237', '/**', 'authc', 88, '需要认证authc');
INSERT INTO `sys_auth_filter` VALUES ('fffffffff3b5807e000000003f2cafff', '/', 'anon', 9, '默认跳转的页面');

-- ----------------------------
-- Table structure for sys_menu
-- ----------------------------
DROP TABLE IF EXISTS `sys_menu`;
CREATE TABLE `sys_menu`  (
  `kid` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'id主键',
  `name` varchar(12) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '菜单名称',
  `permission` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '菜单标识(权限标识)',
  `category` smallint(0) UNSIGNED NOT NULL DEFAULT 1 COMMENT '权限类型(1查询;2编辑;3删除;4添加)',
  `icon_style` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL DEFAULT 'menu-icon fa fa-caret-right' COMMENT '元素span后面的i元素样式',
  `pid` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL DEFAULT '88888888888888888888888888888888' COMMENT '父级id',
  `url` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL DEFAULT 'javascript:;' COMMENT 'url路径',
  `subset` smallint(0) UNSIGNED NOT NULL DEFAULT 0 COMMENT '是否含子节点(1含子节点;0不含)',
  `type` smallint(0) UNSIGNED NOT NULL DEFAULT 1 COMMENT '菜单类型(1导航菜单;2普通按钮;3行内按钮)',
  `relation` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL DEFAULT '88888888888888888888888888888888' COMMENT '菜单层次级别关系(限制最多就8级导航菜单)',
  `order_by` smallint(0) UNSIGNED NOT NULL DEFAULT 1 COMMENT '排序',
  PRIMARY KEY (`kid`) USING BTREE,
  UNIQUE INDEX `index_menu_permission`(`permission`) USING BTREE,
  UNIQUE INDEX `index_menu_url`(`url`) USING BTREE,
  UNIQUE INDEX `index_menu_relation`(`relation`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '系统菜单' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_menu
-- ----------------------------
INSERT INTO `sys_menu` VALUES ('0000000006a9099300000000100d10cd', '获取数据列表[搜索]', 'menu:btn:listData', 1, 'menu-icon fa fa-caret-right', 'ffffffffe56e8ef0ffffffff912af74a', 'menu/listData', 0, 2, 'ffffffff8b559df0ffffffff834bba04@ffffffffe56e8ef0ffffffff912af74a@0000000006a9099300000000100d10cd', 1);
INSERT INTO `sys_menu` VALUES ('000000000ba93c43ffffffffe5c59508', '添加', 'menu:btn:add', 1, 'menu-icon fa fa-caret-right', 'ffffffffe56e8ef0ffffffff912af74a', 'menu/add', 0, 2, 'ffffffff8b559df0ffffffff834bba04@ffffffffe56e8ef0ffffffff912af74a@000000000ba93c43ffffffffe5c59508', 2);
INSERT INTO `sys_menu` VALUES ('000000002d8402d60000000072f7dea2', '获取数据列表[搜索]', 'user:btn:listData', 1, 'menu-icon fa fa-caret-right', 'ffffffff8c468a55ffffffff8f59d635', 'user/listData', 0, 2, 'ffffffff8b559df0ffffffff834bba04@ffffffff8c468a55ffffffff8f59d635@000000002d8402d60000000072f7dea2', 1);
INSERT INTO `sys_menu` VALUES ('000000002e18cf48ffffffffab242e16', '角色菜单(保存菜单)', 'role:row:saveRoleMenu', 4, 'menu-icon fa fa-caret-right', '111fffffbd911aa0ffffffffd5637fff', 'role/saveRoleMenu', 0, 2, 'ffffffff8b559df0ffffffff834bba04@111fffffbd911aa0ffffffffd5637fff@000000002e18cf48ffffffffab242e16', 8);
INSERT INTO `sys_menu` VALUES ('0000000035fbca03000000003a33d6b7', '删除(批量删除)', 'user:btn:delByKeys', 3, 'menu-icon fa fa-caret-right', 'ffffffff8c468a55ffffffff8f59d635', 'user/delByKeys', 0, 2, 'ffffffff8b559df0ffffffff834bba04@ffffffff8c468a55ffffffff8f59d635@0000000035fbca03000000003a33d6b7', 5);
INSERT INTO `sys_menu` VALUES ('000000003a56d4fb0000000037016444', '角色(保存角色)', 'user:btn_row:saveAllotRole', 4, 'menu-icon fa fa-caret-right', 'ffffffff8c468a55ffffffff8f59d635', 'user/saveAllotRole', 0, 2, 'ffffffff8b559df0ffffffff834bba04@ffffffff8c468a55ffffffff8f59d635@000000003a56d4fb0000000037016444', 9);
INSERT INTO `sys_menu` VALUES ('0000000058e2ec83000000002f978e03', '编辑', 'menu:row:edit', 2, 'menu-icon fa fa-caret-right', 'ffffffffe56e8ef0ffffffff912af74a', 'menu/edit', 0, 3, 'ffffffff8b559df0ffffffff834bba04@ffffffffe56e8ef0ffffffff912af74a@0000000058e2ec83000000002f978e03', 4);
INSERT INTO `sys_menu` VALUES ('000000005c41138100000000288a6b45', '删除', 'menu:row:delById', 3, 'menu-icon fa fa-caret-right', 'ffffffffe56e8ef0ffffffff912af74a', 'menu/delById', 0, 3, 'ffffffff8b559df0ffffffff834bba04@ffffffffe56e8ef0ffffffff912af74a@000000005c41138100000000288a6b45', 3);
INSERT INTO `sys_menu` VALUES ('000000007330a2a9ffffffff98cebe66', '添加', 'user:btn:add', 4, 'menu-icon fa fa-caret-right', 'ffffffff8c468a55ffffffff8f59d635', 'user/add', 0, 2, 'ffffffff8b559df0ffffffff834bba04@ffffffff8c468a55ffffffff8f59d635@000000007330a2a9ffffffff98cebe66', 2);
INSERT INTO `sys_menu` VALUES ('0000000077224459ffffffffc9d752ca', '启用禁用', 'user:row:editEnabled', 2, 'menu-icon fa fa-caret-right', 'ffffffff8c468a55ffffffff8f59d635', 'user/editEnabled', 0, 3, 'ffffffff8b559df0ffffffff834bba04@ffffffff8c468a55ffffffff8f59d635@0000000077224459ffffffffc9d752ca', 10);
INSERT INTO `sys_menu` VALUES ('000000007937b8de0000000034ef3b70', '清空菜单', 'role:row:delEmptyMenu', 3, 'menu-icon fa fa-caret-right', '111fffffbd911aa0ffffffffd5637fff', 'role/delEmptyMenu', 0, 3, 'ffffffff8b559df0ffffffff834bba04@111fffffbd911aa0ffffffffd5637fff@000000007937b8de0000000034ef3b70', 6);
INSERT INTO `sys_menu` VALUES ('000000007a3bebc1ffffffffc0d19222', '角色(获取角色)', 'user:btn_row:getAllotRole', 1, 'menu-icon fa fa-caret-right', 'ffffffff8c468a55ffffffff8f59d635', 'user/getAllotRole', 0, 2, 'ffffffff8b559df0ffffffff834bba04@ffffffff8c468a55ffffffff8f59d635@000000007a3bebc1ffffffffc0d19222', 8);
INSERT INTO `sys_menu` VALUES ('000000007ea75783000000004607fdec', '编辑', 'user:row:edit', 2, 'menu-icon fa fa-caret-right', 'ffffffff8c468a55ffffffff8f59d635', 'user/edit', 0, 3, 'ffffffff8b559df0ffffffff834bba04@ffffffff8c468a55ffffffff8f59d635@000000007ea75783000000004607fdec', 3);
INSERT INTO `sys_menu` VALUES ('1111ffffe56e8ef0ffffffff912af111', '主页面', 'page:main', 1, 'menu-icon fa fa-caret-right', '88888888888888888888888888888888', 'main', 0, 1, '1111ffffe56e8ef0ffffffff912af111', 1);
INSERT INTO `sys_menu` VALUES ('111fffffbd911aa0ffffffffd5637fff', '角色权限', 'page:sys_role', 1, 'menu-icon fa fa-caret-right', 'ffffffff8b559df0ffffffff834bba04', 'sys_role', 0, 1, 'ffffffff8b559df0ffffffff834bba04@111fffffbd911aa0ffffffffd5637fff', 3);
INSERT INTO `sys_menu` VALUES ('ffffffff87212d7d000000005fbd6e98', '添加', 'role:btn:add', 4, 'menu-icon fa fa-caret-right', '111fffffbd911aa0ffffffffd5637fff', 'role/add', 0, 2, 'ffffffff8b559df0ffffffff834bba04@111fffffbd911aa0ffffffffd5637fff@ffffffff87212d7d000000005fbd6e98', 2);
INSERT INTO `sys_menu` VALUES ('ffffffff8b559df0ffffffff834bba04', '系统设置', 'page:sys_setting', 1, 'menu-icon fa fa-cog', '88888888888888888888888888888888', 'sys_setting', 1, 1, 'ffffffff8b559df0ffffffff834bba04', 1);
INSERT INTO `sys_menu` VALUES ('ffffffff8c468a55ffffffff8f59d635', '用户账号', 'page:sys_user', 1, 'menu-icon fa fa-caret-right', 'ffffffff8b559df0ffffffff834bba04', 'sys_user', 0, 1, 'ffffffff8b559df0ffffffff834bba04@ffffffff8c468a55ffffffff8f59d635', 2);
INSERT INTO `sys_menu` VALUES ('ffffffff8e6151ff0000000015f6e145', '删除(行内删除)', 'role:row:delById', 3, 'menu-icon fa fa-caret-right', '111fffffbd911aa0ffffffffd5637fff', 'role/delById', 0, 3, 'ffffffff8b559df0ffffffff834bba04@111fffffbd911aa0ffffffffd5637fff@ffffffff8e6151ff0000000015f6e145', 4);
INSERT INTO `sys_menu` VALUES ('ffffffff93f9086effffffffb4a239cd', '删除(批量删除)', 'role:btn:delByKeys', 3, 'menu-icon fa fa-caret-right', '111fffffbd911aa0ffffffffd5637fff', 'role/delByKeys', 0, 2, 'ffffffff8b559df0ffffffff834bba04@111fffffbd911aa0ffffffffd5637fff@ffffffff93f9086effffffffb4a239cd', 5);
INSERT INTO `sys_menu` VALUES ('ffffffff9db05c1000000000002e5179', '私有菜单(获取菜单)', 'user:row:getOwnMenu', 1, 'menu-icon fa fa-caret-right', 'ffffffff8c468a55ffffffff8f59d635', 'user/getOwnMenu', 0, 3, 'ffffffff8b559df0ffffffff834bba04@ffffffff8c468a55ffffffff8f59d635@ffffffff9db05c1000000000002e5179', 6);
INSERT INTO `sys_menu` VALUES ('ffffffff9dcbdcebffffffff99573f80', '私有菜单(保存菜单)', 'user:row:saveOwnMenu', 4, 'menu-icon fa fa-caret-right', 'ffffffff8c468a55ffffffff8f59d635', 'user/saveOwnMenu', 0, 3, 'ffffffff8b559df0ffffffff834bba04@ffffffff8c468a55ffffffff8f59d635@ffffffff9dcbdcebffffffff99573f80', 7);
INSERT INTO `sys_menu` VALUES ('ffffffffb71281a2ffffffffd931eb95', '删除(行内删除)', 'user:row:delById', 3, 'menu-icon fa fa-caret-right', 'ffffffff8c468a55ffffffff8f59d635', 'user/delById', 0, 3, 'ffffffff8b559df0ffffffff834bba04@ffffffff8c468a55ffffffff8f59d635@ffffffffb71281a2ffffffffd931eb95', 4);
INSERT INTO `sys_menu` VALUES ('ffffffffc43097b8000000003a72e62f', '权限菜单', 'user:row:getMenuData', 1, 'menu-icon fa fa-caret-right', 'ffffffff8c468a55ffffffff8f59d635', 'user/getMenuData', 0, 3, 'ffffffff8b559df0ffffffff834bba04@ffffffff8c468a55ffffffff8f59d635@ffffffffc43097b8000000003a72e62f', 11);
INSERT INTO `sys_menu` VALUES ('ffffffffdae3cd4affffffff9894b623', '角色菜单(获取菜单)', 'role:row:getRoleMenu', 1, 'menu-icon fa fa-caret-right', '111fffffbd911aa0ffffffffd5637fff', 'role/getRoleMenu', 0, 2, 'ffffffff8b559df0ffffffff834bba04@111fffffbd911aa0ffffffffd5637fff@ffffffffdae3cd4affffffff9894b623', 7);
INSERT INTO `sys_menu` VALUES ('ffffffffddf9f51ffffffffff6157ca3', '根据id获取详情', 'menu:row:queryById', 1, 'menu-icon fa fa-caret-right', 'ffffffffe56e8ef0ffffffff912af74a', 'menu/queryById', 0, 3, 'ffffffff8b559df0ffffffff834bba04@ffffffffe56e8ef0ffffffff912af74a@ffffffffddf9f51ffffffffff6157ca3', 6);
INSERT INTO `sys_menu` VALUES ('ffffffffdfaf333c000000001760f4a5', '编辑', 'role:row:edit', 2, 'menu-icon fa fa-caret-right', '111fffffbd911aa0ffffffffd5637fff', 'role/edit', 0, 3, 'ffffffff8b559df0ffffffff834bba04@111fffffbd911aa0ffffffffd5637fff@ffffffffdfaf333c000000001760f4a5', 3);
INSERT INTO `sys_menu` VALUES ('ffffffffe56e8ef0ffffffff912af74a', '菜单管理', 'page:sys_menu', 1, 'menu-icon fa fa-caret-right', 'ffffffff8b559df0ffffffff834bba04', 'sys_menu', 0, 1, 'ffffffff8b559df0ffffffff834bba04@ffffffffe56e8ef0ffffffff912af74a', 1);
INSERT INTO `sys_menu` VALUES ('fffffffff051bf04ffffffffa2ae3c8e', '获取树形菜单', 'menu:btn:queryTreeMenu', 1, 'menu-icon fa fa-caret-right', 'ffffffffe56e8ef0ffffffff912af74a', 'menu/queryTreeMenu', 0, 2, 'ffffffff8b559df0ffffffff834bba04@ffffffffe56e8ef0ffffffff912af74a@fffffffff051bf04ffffffffa2ae3c8e', 5);
INSERT INTO `sys_menu` VALUES ('fffffffffaad7649ffffffffe7c3d6a6', '获取数据列表[搜索]', 'role:btn:listData', 1, 'menu-icon fa fa-caret-right', '111fffffbd911aa0ffffffffd5637fff', 'role/listData', 0, 2, 'ffffffff8b559df0ffffffff834bba04@111fffffbd911aa0ffffffffd5637fff@fffffffffaad7649ffffffffe7c3d6a6', 1);

-- ----------------------------
-- Table structure for sys_role
-- ----------------------------
DROP TABLE IF EXISTS `sys_role`;
CREATE TABLE `sys_role`  (
  `kid` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'id主键',
  `role_name` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '角色名称',
  `role_flag` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '角色标识',
  PRIMARY KEY (`kid`) USING BTREE,
  UNIQUE INDEX `index_role_name`(`role_name`) USING BTREE,
  UNIQUE INDEX `index_role_flag`(`role_flag`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '系统角色' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_role
-- ----------------------------
INSERT INTO `sys_role` VALUES ('000000003035dacf000000000c087217', '游客', 'guest');
INSERT INTO `sys_role` VALUES ('ffffffffa04b32a6ffffffffba40a72e', '系统管理员', 'administrators');
INSERT INTO `sys_role` VALUES ('ffffffffdc2ebe6a000000006b149e18', '操作员', 'operator');
INSERT INTO `sys_role` VALUES ('ffffffffde90da3fffffffffdef7150f', '管理员', 'admin');

-- ----------------------------
-- Table structure for sys_role_menu
-- ----------------------------
DROP TABLE IF EXISTS `sys_role_menu`;
CREATE TABLE `sys_role_menu`  (
  `kid` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'id主键',
  `role_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '角色的id(sys_role.kid)',
  `menu_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '菜单的id(sys_menu.kid)',
  PRIMARY KEY (`kid`) USING BTREE,
  INDEX `index_role_menu`(`role_id`, `menu_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '角色权限(菜单)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_role_menu
-- ----------------------------
INSERT INTO `sys_role_menu` VALUES ('ffffffffde8d2ccfffffffff910aa381', '000000003035dacf000000000c087217', '0000000006a9099300000000100d10cd');
INSERT INTO `sys_role_menu` VALUES ('ffffffffcfebf5d30000000030741487', '000000003035dacf000000000c087217', '000000000ba93c43ffffffffe5c59508');
INSERT INTO `sys_role_menu` VALUES ('000000007b41b28900000000474b30cc', '000000003035dacf000000000c087217', '0000000058e2ec83000000002f978e03');
INSERT INTO `sys_role_menu` VALUES ('000000001413f11f000000006d6bb955', '000000003035dacf000000000c087217', '000000005c41138100000000288a6b45');
INSERT INTO `sys_role_menu` VALUES ('000000005bd28f74000000002a1625c3', '000000003035dacf000000000c087217', '1111ffffe56e8ef0ffffffff912af111');
INSERT INTO `sys_role_menu` VALUES ('00000000067b29f40000000055e1584f', '000000003035dacf000000000c087217', '111fffffbd911aa0ffffffffd5637fff');
INSERT INTO `sys_role_menu` VALUES ('fffffffffcb6f5dffffffffff82bd971', '000000003035dacf000000000c087217', 'ffffffff8b559df0ffffffff834bba04');
INSERT INTO `sys_role_menu` VALUES ('0000000008c524cfffffffffa06098af', '000000003035dacf000000000c087217', 'ffffffff8c468a55ffffffff8f59d635');
INSERT INTO `sys_role_menu` VALUES ('000000003aa0e7eaffffffffccbfcfb6', '000000003035dacf000000000c087217', 'ffffffffe56e8ef0ffffffff912af74a');
INSERT INTO `sys_role_menu` VALUES ('000000007f13261d000000005501c6d7', 'ffffffffde90da3fffffffffdef7150f', '0000000006a9099300000000100d10cd');
INSERT INTO `sys_role_menu` VALUES ('ffffffffcab349520000000001497712', 'ffffffffde90da3fffffffffdef7150f', '000000000ba93c43ffffffffe5c59508');
INSERT INTO `sys_role_menu` VALUES ('0000000015f6a64cffffffffee690a58', 'ffffffffde90da3fffffffffdef7150f', '000000002d8402d60000000072f7dea2');
INSERT INTO `sys_role_menu` VALUES ('0000000051b979070000000009b1da20', 'ffffffffde90da3fffffffffdef7150f', '000000002e18cf48ffffffffab242e16');
INSERT INTO `sys_role_menu` VALUES ('000000002e429313ffffffff8924e3aa', 'ffffffffde90da3fffffffffdef7150f', '0000000035fbca03000000003a33d6b7');
INSERT INTO `sys_role_menu` VALUES ('00000000059cb90b0000000016dbd9ae', 'ffffffffde90da3fffffffffdef7150f', '000000003a56d4fb0000000037016444');
INSERT INTO `sys_role_menu` VALUES ('ffffffffaf9dd1f0ffffffff84e6a2b9', 'ffffffffde90da3fffffffffdef7150f', '0000000058e2ec83000000002f978e03');
INSERT INTO `sys_role_menu` VALUES ('000000006c762becffffffff8179e1d6', 'ffffffffde90da3fffffffffdef7150f', '000000005c41138100000000288a6b45');
INSERT INTO `sys_role_menu` VALUES ('ffffffffac3151100000000008dfdeaf', 'ffffffffde90da3fffffffffdef7150f', '000000007330a2a9ffffffff98cebe66');
INSERT INTO `sys_role_menu` VALUES ('0000000066539da5ffffffffc7fc925e', 'ffffffffde90da3fffffffffdef7150f', '0000000077224459ffffffffc9d752ca');
INSERT INTO `sys_role_menu` VALUES ('ffffffffda4a14f80000000033214822', 'ffffffffde90da3fffffffffdef7150f', '000000007937b8de0000000034ef3b70');
INSERT INTO `sys_role_menu` VALUES ('ffffffffa0edaa8affffffffb94715a5', 'ffffffffde90da3fffffffffdef7150f', '000000007a3bebc1ffffffffc0d19222');
INSERT INTO `sys_role_menu` VALUES ('000000007e7260280000000029f56bf3', 'ffffffffde90da3fffffffffdef7150f', '000000007ea75783000000004607fdec');
INSERT INTO `sys_role_menu` VALUES ('ffffffffe3b6e977ffffffffab7b642f', 'ffffffffde90da3fffffffffdef7150f', '1111ffffe56e8ef0ffffffff912af111');
INSERT INTO `sys_role_menu` VALUES ('0000000075bf785b00000000088f043c', 'ffffffffde90da3fffffffffdef7150f', '111fffffbd911aa0ffffffffd5637fff');
INSERT INTO `sys_role_menu` VALUES ('000000004e5ad468ffffffffc856bd87', 'ffffffffde90da3fffffffffdef7150f', 'ffffffff87212d7d000000005fbd6e98');
INSERT INTO `sys_role_menu` VALUES ('ffffffffd9694ae2ffffffffda58e1e9', 'ffffffffde90da3fffffffffdef7150f', 'ffffffff8b559df0ffffffff834bba04');
INSERT INTO `sys_role_menu` VALUES ('000000001f274cca0000000047ee700a', 'ffffffffde90da3fffffffffdef7150f', 'ffffffff8c468a55ffffffff8f59d635');
INSERT INTO `sys_role_menu` VALUES ('ffffffffd1738955000000003a996a36', 'ffffffffde90da3fffffffffdef7150f', 'ffffffff8e6151ff0000000015f6e145');
INSERT INTO `sys_role_menu` VALUES ('ffffffff9c4cac760000000022bd5488', 'ffffffffde90da3fffffffffdef7150f', 'ffffffff93f9086effffffffb4a239cd');
INSERT INTO `sys_role_menu` VALUES ('ffffffffc87fe8ffffffffffcfc843df', 'ffffffffde90da3fffffffffdef7150f', 'ffffffff9db05c1000000000002e5179');
INSERT INTO `sys_role_menu` VALUES ('0000000047d80a99ffffffffc205ac44', 'ffffffffde90da3fffffffffdef7150f', 'ffffffff9dcbdcebffffffff99573f80');
INSERT INTO `sys_role_menu` VALUES ('0000000006ff4e28000000006c885a32', 'ffffffffde90da3fffffffffdef7150f', 'ffffffffb71281a2ffffffffd931eb95');
INSERT INTO `sys_role_menu` VALUES ('0000000043a67e9d00000000647ef271', 'ffffffffde90da3fffffffffdef7150f', 'ffffffffc43097b8000000003a72e62f');
INSERT INTO `sys_role_menu` VALUES ('00000000257d3332ffffffffff7dfd87', 'ffffffffde90da3fffffffffdef7150f', 'ffffffffdae3cd4affffffff9894b623');
INSERT INTO `sys_role_menu` VALUES ('fffffffff2b0e39cffffffffa5b49f53', 'ffffffffde90da3fffffffffdef7150f', 'ffffffffddf9f51ffffffffff6157ca3');
INSERT INTO `sys_role_menu` VALUES ('000000002607c45700000000692f29be', 'ffffffffde90da3fffffffffdef7150f', 'ffffffffdfaf333c000000001760f4a5');
INSERT INTO `sys_role_menu` VALUES ('ffffffffca6eb0bc0000000067d4b168', 'ffffffffde90da3fffffffffdef7150f', 'ffffffffe56e8ef0ffffffff912af74a');
INSERT INTO `sys_role_menu` VALUES ('ffffffffd4bce7fd000000007059a35b', 'ffffffffde90da3fffffffffdef7150f', 'fffffffff051bf04ffffffffa2ae3c8e');
INSERT INTO `sys_role_menu` VALUES ('00000000171b3488ffffffffbc99ca78', 'ffffffffde90da3fffffffffdef7150f', 'fffffffffaad7649ffffffffe7c3d6a6');

-- ----------------------------
-- Table structure for sys_user
-- ----------------------------
DROP TABLE IF EXISTS `sys_user`;
CREATE TABLE `sys_user`  (
  `kid` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'id主键',
  `user_name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户名|账号',
  `type` smallint(0) UNSIGNED NOT NULL DEFAULT 1 COMMENT '用户名|账号类型(1系统账号;2注册账号;)',
  `add_date` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '添加时间',
  `enabled` smallint(0) UNSIGNED NOT NULL DEFAULT 0 COMMENT '是否冻结（0正常1冻结）',
  `logintime` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '最后登录时间',
  `times` int(0) UNSIGNED NOT NULL DEFAULT 1 COMMENT '已成功登录次数,默认为1，每次累加1',
  `error_count` smallint(0) UNSIGNED NOT NULL DEFAULT 0 COMMENT '登录错误次数',
  `error_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '记录登录错误的时刻',
  PRIMARY KEY (`kid`) USING BTREE,
  UNIQUE INDEX `index_user_name`(`user_name`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '系统用户' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_user
-- ----------------------------
INSERT INTO `sys_user` VALUES ('ffffffff95beb47dffffffffad7e6abe', 'administrator', 1, '2020-04-15 22:39:30', 0, '2020-04-17 16:43:45', 5, 0, '2020-04-17 16:43:45');
INSERT INTO `sys_user` VALUES ('ffffffffab9fc98dffffffff8b642b39', 'menu', 1, '2020-04-15 22:42:01', 0, '2020-04-15 22:43:09', 3, 0, '2020-04-15 22:43:09');
INSERT INTO `sys_user` VALUES ('ffffffffbd471a55ffffffff976c6d1b', 'typ', 1, '2020-04-13 19:55:34', 0, '2020-05-01 12:51:59', 78, 0, '2020-05-01 12:51:59');
INSERT INTO `sys_user` VALUES ('ffffffffd4506238ffffffffc9dada9a', 'wcf', 1, '2020-04-27 22:57:04', 0, '2020-04-28 23:42:19', 13, 0, '2020-04-28 23:42:20');
INSERT INTO `sys_user` VALUES ('ffffffffddf9f1ffffffffff88888888', 'admin', 1, '2020-03-18 16:49:48', 0, '2020-05-09 09:57:34', 73, 0, '2020-05-09 09:57:34');

-- ----------------------------
-- Table structure for sys_user_menu
-- ----------------------------
DROP TABLE IF EXISTS `sys_user_menu`;
CREATE TABLE `sys_user_menu`  (
  `kid` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户菜单(私有菜单)id',
  `user_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户id(sys_user.kid)',
  `menu_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '菜单id(sys_menu.kid)',
  PRIMARY KEY (`kid`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '用户菜单(私有菜单)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_user_menu
-- ----------------------------
INSERT INTO `sys_user_menu` VALUES ('68dc9cc27f2711eaa7d300505625d758', 'ffffffffab9fc98dffffffff8b642b39', '1111ffffe56e8ef0ffffffff912af111');
INSERT INTO `sys_user_menu` VALUES ('68dc9ee27f2711eaa7d300505625d758', 'ffffffffab9fc98dffffffff8b642b39', 'ffffffff8b559df0ffffffff834bba04');
INSERT INTO `sys_user_menu` VALUES ('68dca1057f2711eaa7d300505625d758', 'ffffffffab9fc98dffffffff8b642b39', 'ffffffffe56e8ef0ffffffff912af74a');
INSERT INTO `sys_user_menu` VALUES ('68dca1837f2711eaa7d300505625d758', 'ffffffffab9fc98dffffffff8b642b39', '0000000006a9099300000000100d10cd');
INSERT INTO `sys_user_menu` VALUES ('68dca1ce7f2711eaa7d300505625d758', 'ffffffffab9fc98dffffffff8b642b39', '000000000ba93c43ffffffffe5c59508');
INSERT INTO `sys_user_menu` VALUES ('68dca2157f2711eaa7d300505625d758', 'ffffffffab9fc98dffffffff8b642b39', '000000005c41138100000000288a6b45');
INSERT INTO `sys_user_menu` VALUES ('68dca2587f2711eaa7d300505625d758', 'ffffffffab9fc98dffffffff8b642b39', '0000000058e2ec83000000002f978e03');
INSERT INTO `sys_user_menu` VALUES ('68dca29a7f2711eaa7d300505625d758', 'ffffffffab9fc98dffffffff8b642b39', 'fffffffff051bf04ffffffffa2ae3c8e');
INSERT INTO `sys_user_menu` VALUES ('68dca2df7f2711eaa7d300505625d758', 'ffffffffab9fc98dffffffff8b642b39', 'ffffffffddf9f51ffffffffff6157ca3');
INSERT INTO `sys_user_menu` VALUES ('7976d1168b6711ea978d02004a400001', 'ffffffffbd471a55ffffffff976c6d1b', 'ffffffff8b559df0ffffffff834bba04');
INSERT INTO `sys_user_menu` VALUES ('7976d56b8b6711ea978d02004a400001', 'ffffffffbd471a55ffffffff976c6d1b', 'ffffffff8c468a55ffffffff8f59d635');
INSERT INTO `sys_user_menu` VALUES ('7976d6588b6711ea978d02004a400001', 'ffffffffbd471a55ffffffff976c6d1b', '000000007330a2a9ffffffff98cebe66');
INSERT INTO `sys_user_menu` VALUES ('7976d7008b6711ea978d02004a400001', 'ffffffffbd471a55ffffffff976c6d1b', '000000007ea75783000000004607fdec');
INSERT INTO `sys_user_menu` VALUES ('7976d7aa8b6711ea978d02004a400001', 'ffffffffbd471a55ffffffff976c6d1b', '1111ffffe56e8ef0ffffffff912af111');
INSERT INTO `sys_user_menu` VALUES ('b8d76f1a889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', '1111ffffe56e8ef0ffffffff912af111');
INSERT INTO `sys_user_menu` VALUES ('b8d77304889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', 'ffffffff8b559df0ffffffff834bba04');
INSERT INTO `sys_user_menu` VALUES ('b8d773cd889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', 'ffffffffe56e8ef0ffffffff912af74a');
INSERT INTO `sys_user_menu` VALUES ('b8d77489889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', '0000000006a9099300000000100d10cd');
INSERT INTO `sys_user_menu` VALUES ('b8d77504889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', '000000000ba93c43ffffffffe5c59508');
INSERT INTO `sys_user_menu` VALUES ('b8d7756a889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', '000000005c41138100000000288a6b45');
INSERT INTO `sys_user_menu` VALUES ('b8d775c9889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', '0000000058e2ec83000000002f978e03');
INSERT INTO `sys_user_menu` VALUES ('b8d77695889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', 'fffffffff051bf04ffffffffa2ae3c8e');
INSERT INTO `sys_user_menu` VALUES ('b8d776f8889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', 'ffffffffddf9f51ffffffffff6157ca3');
INSERT INTO `sys_user_menu` VALUES ('b8d77751889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', 'ffffffff8c468a55ffffffff8f59d635');
INSERT INTO `sys_user_menu` VALUES ('b8d777b0889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', '000000002d8402d60000000072f7dea2');
INSERT INTO `sys_user_menu` VALUES ('b8d77824889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', '000000007330a2a9ffffffff98cebe66');
INSERT INTO `sys_user_menu` VALUES ('b8d77891889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', '000000007ea75783000000004607fdec');
INSERT INTO `sys_user_menu` VALUES ('b8d778f4889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', 'ffffffffb71281a2ffffffffd931eb95');
INSERT INTO `sys_user_menu` VALUES ('b8d7794e889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', '0000000035fbca03000000003a33d6b7');
INSERT INTO `sys_user_menu` VALUES ('b8d779a8889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', 'ffffffff9db05c1000000000002e5179');
INSERT INTO `sys_user_menu` VALUES ('b8d77a05889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', 'ffffffff9dcbdcebffffffff99573f80');
INSERT INTO `sys_user_menu` VALUES ('b8d77a5f889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', '000000007a3bebc1ffffffffc0d19222');
INSERT INTO `sys_user_menu` VALUES ('b8d77ab4889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', '000000003a56d4fb0000000037016444');
INSERT INTO `sys_user_menu` VALUES ('b8d77b07889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', '0000000077224459ffffffffc9d752ca');
INSERT INTO `sys_user_menu` VALUES ('b8d77b5f889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', 'ffffffffc43097b8000000003a72e62f');
INSERT INTO `sys_user_menu` VALUES ('b8d77bcf889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', '111fffffbd911aa0ffffffffd5637fff');
INSERT INTO `sys_user_menu` VALUES ('b8d77c31889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', 'fffffffffaad7649ffffffffe7c3d6a6');
INSERT INTO `sys_user_menu` VALUES ('b8d77c8d889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', 'ffffffff87212d7d000000005fbd6e98');
INSERT INTO `sys_user_menu` VALUES ('b8d77ce3889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', 'ffffffffdfaf333c000000001760f4a5');
INSERT INTO `sys_user_menu` VALUES ('b8d77d3b889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', 'ffffffff8e6151ff0000000015f6e145');
INSERT INTO `sys_user_menu` VALUES ('b8d77d8d889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', 'ffffffff93f9086effffffffb4a239cd');
INSERT INTO `sys_user_menu` VALUES ('b8d77de6889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', '000000007937b8de0000000034ef3b70');
INSERT INTO `sys_user_menu` VALUES ('b8d77e3a889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', 'ffffffffdae3cd4affffffff9894b623');
INSERT INTO `sys_user_menu` VALUES ('b8d77e8f889811ea978d02004a400001', 'ffffffffd4506238ffffffffc9dada9a', '000000002e18cf48ffffffffab242e16');

-- ----------------------------
-- Table structure for sys_user_password
-- ----------------------------
DROP TABLE IF EXISTS `sys_user_password`;
CREATE TABLE `sys_user_password`  (
  `user_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'user主键(sys_user.kid)',
  `user_password` char(40) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户账号密码',
  PRIMARY KEY (`user_id`) USING BTREE,
  UNIQUE INDEX `index_user_name`(`user_password`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '用户密码' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_user_password
-- ----------------------------
INSERT INTO `sys_user_password` VALUES ('ffffffffddf9f1ffffffffff88888888', '3e7dd55ca11410b0a84b8541e9358fafb816e065');
INSERT INTO `sys_user_password` VALUES ('ffffffffab9fc98dffffffff8b642b39', '867e84b91c189939fdc6391232328d412d8d8f97');
INSERT INTO `sys_user_password` VALUES ('ffffffffbd471a55ffffffff976c6d1b', '99f8a8d21ddf3a8ec1a1b748bc8c9967b4daa558');
INSERT INTO `sys_user_password` VALUES ('ffffffff95beb47dffffffffad7e6abe', 'a70e26f1d816e2a67bfe82533ec2cc89212d3b40');
INSERT INTO `sys_user_password` VALUES ('ffffffffd4506238ffffffffc9dada9a', 'b733ccfde20484ef69d69d2e0b6f5cc053c61c4b');

-- ----------------------------
-- Table structure for sys_user_role
-- ----------------------------
DROP TABLE IF EXISTS `sys_user_role`;
CREATE TABLE `sys_user_role`  (
  `kid` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'id主键',
  `user_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户名|账号的id(sys_user.kid)',
  `role_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '角色的id(sys_role.kid)',
  PRIMARY KEY (`kid`) USING BTREE,
  UNIQUE INDEX `index_user_role`(`user_id`, `role_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '用户角色' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_user_role
-- ----------------------------
INSERT INTO `sys_user_role` VALUES ('ffffffffa04b32a6ffffffffba40ffff', 'ffffffffddf9f1ffffffffff88888888', 'ffffffffa04b32a6ffffffffba40a72e');
INSERT INTO `sys_user_role` VALUES ('fffffffff051bf04ffffffffa2afffff', 'ffffffffddf9f1ffffffffff88888888', 'ffffffffde90da3fffffffffdef7150f');

-- ----------------------------
-- View structure for view_user_login
-- ----------------------------
DROP VIEW IF EXISTS `view_user_login`;
CREATE ALGORITHM = UNDEFINED SQL SECURITY DEFINER VIEW `view_user_login` AS select `su`.`kid` AS `kid`,`su`.`user_name` AS `user_name`,`sup`.`user_password` AS `user_password`,`su`.`enabled` AS `enabled`,`su`.`error_count` AS `error_count`,`su`.`error_time` AS `error_time` from (`sys_user` `su` join `sys_user_password` `sup`) where (`su`.`kid` = `sup`.`user_id`);

SET FOREIGN_KEY_CHECKS = 1;
