shiro-velocity-support
==============

在 velocity 模板文件中，实现 shiro 权限验证
在 applicationContext.xml 只有此功能的核心配置的例子，其它相关配置不属于此项目范围之类。
velocityToolBox.xml 文件中也只列出了，该功能的配置。

使用方法：

	一、$shiro.isAuthenticated()
		功能说明：验证是否为已认证通过的用户，不包含已记住的用户，这是与 isUser 标签方法的区别所在。
		参数：无
		返回值：Boolean

	二、$shiro.isNotAuthenticated()
		功能说明：验证是否为未认证通过用户，与 isAuthenticated 标签相对应，与 isGuest 标签的区别是，该标签包含已记住用户。
		参数：无
		返回值：Boolean

	三、$shiro.isGuest()
		功能说明：验证当前用户是否为“访客”，即未认证（包含未记住）的用户。
		参数：无
		返回值：Boolean

	四、$shiro.isUser()
		功能说明：验证当前用户是否认证通过或已记住的用户。
		参数：无
		返回值：Boolean

	五、$shiro.getPrincipal()
		功能说明：获取当前用户 Principal。
		参数：无
		返回值：Object

	六、$shiro.getPrincipalProperty(String property)
		功能说明：获取当前用户 Principal。
		参数：String property 用户属性
		返回值：Object

	七、$shiro.hasRole(String role)
		功能说明：验证当前用户是否属于该角色 。
		参数：String role 角色名称
		返回值：Boolean

	八、$shiro.lacksRole(String role)
		功能说明：验证当前用户是否不属于该角色，与 hasRole 标签逻辑相反。
		参数：String role 角色名称
		返回值：Boolean

	九、$shiro.hasAnyRoles(String roleNames, String delimeter)
		功能说明：验证当前用户是否属于以下任意一个角色。
		参数：String roleNames 用户角色列表，以 delimeter 分割
			  String delimeter 用户角色分隔符
		返回值：Boolean

	十、$shiro.hasAnyRoles(String roleNames)
		功能说明：验证当前用户是否属于以下任意一个角色。
		参数：String roleNames 用户角色列表，以 “," 分割
		返回值：Boolean

	十一、$shiro.hasAnyRoles(Collection<String> roleNames)
		功能说明：验证当前用户是否属于以下任意一个角色。
		参数：Collection<String> roleNames 用户权限角色
		返回值：Boolean

	十二、$shiro.hasAnyRoles(String[] roleNames)
		功能说明：验证当前用户是否属于以下任意一个角色。
		参数：String[] roleNames 用户权限角色
		返回值：Boolean

	十三、$shiro.hasPermission(String permission)
		功能说明：验证当前用户是否拥有指定权限
		参数：String permission 权限名称
		返回值：Boolean

	十四、$shiro.lacksPermission(String permission)
		功能说明：验证当前用户是否不拥有指定权限，与 hasPermission 逻辑相反。
		参数：String permission 权限名称
		返回值：Boolean

	十五、$shiro.hasAnyPermissions(String permissions, String delimeter)
		功能说明：验证当前用户是否拥有以下任意一个权限。
		参数：String permissions 权限名称列表，以 delimeter 分割
			  String delimeter 用户权限分隔符
		返回值：Boolean

	十六、$shiro.hasAnyPermissions(String permissions)
		功能说明：验证当前用户是否拥有以下任意一个权限。
		参数：String permissions 权限名称列表，以 “," 分割
		返回值：Boolean

	十七、$shiro.hasAnyPermissions(Collection<String> permissions)
		功能说明：验证当前用户是否拥有以下任意一个权限。
		参数：Collection<String> 权限名称列表
		返回值：Boolean

	十八、$shiro.hasAnyPermissions(String[] permissions)
		功能说明：验证当前用户是否拥有以下任意一个权限。
		参数：String[] 权限名称列表
		返回值：Boolean
=======