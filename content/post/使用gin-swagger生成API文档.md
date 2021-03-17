+++
keywords = ["swagger", 'golang']
title = "使用swag生成API文档"
categories = ["golang"]
disqusIdentifier = "gin-swagger"
comments = true
clearReading = true
date = 2021-03-17T16:33:00+08:00
showSocial = false
showPagination = true
showTags = true
showDate = true
+++

## 使用swag生成API文档

### swagger介绍

Swagger是用来描述RESTful API的接口语言，可以帮助开发者自动生成在线API接口文档以及功能测试代码。

[swag](https://github.com/swaggo/swag)可以将golang的注释转化为Swagger 2.0文档，支持多种golang Web框架，可以快速集成到我们的项目中。


### 使用gin-swagger

#### 对接口代码添加注释

为应用添加注释(这里是通用的API信息)

代码示例如下

```
// @title Swagger Example API
// @version 1.0
// @description 这个一个demo
// @contact.name thinkmo
// @contact.email tryit0714@gmail.com
func main(){
}
```

主要注释如下

| 注释                    | 说明                                                                                            | 示例                                                            |
| ----------------------- | ----------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| title                   | **必填** 应用程序的名称。                                                                       | // @title Swagger Example API                                   |
| version                 | **必填** 提供应用程序API的版本。                                                                | // @version 1.0                                                 |
| description             | 应用程序的简短描述。                                                                            | // @description This is a sample server celler server.          |
| tag.name                | 标签的名称。                                                                                    | // @tag.name This is the name of the tag                        |
| tag.description         | 标签的描述。                                                                                    | // @tag.description Cool Description                            |
| tag.docs.url            | 标签的外部文档的URL。                                                                           | // @tag.docs.url https://example.com                            |
| tag.docs.description    | 标签的外部文档说明。                                                                            | // @tag.docs.description Best example documentation             |
| termsOfService          | API的服务条款。                                                                                 | // @termsOfService http://swagger.io/terms/                     |
| contact.name            | 公开的API的联系信息。                                                                           | // @contact.name API Support                                    |
| contact.url             | 联系信息的URL。 必须采用网址格式。                                                              | // @contact.url http://www.swagger.io/support                   |
| contact.email           | 联系人/组织的电子邮件地址。 必须采用电子邮件地址的格式。                                        | // @contact.email support@swagger.io                            |
| license.name            | **必填** 用于API的许可证名称。                                                                  | // @license.name Apache 2.0                                     |
| license.url             | 用于API的许可证的URL。 必须采用网址格式。                                                       | // @license.url http://www.apache.org/licenses/LICENSE-2.0.html |
| host                    | 运行API的主机（主机名或IP地址）。                                                               | // @host localhost:8080                                         |
| BasePath                | 运行API的基本路径。                                                                             | // @BasePath /api/v1                                            |
| query.collection.format | 请求URI query里数组参数的默认格式：csv，multi，pipes，tsv，ssv。 如果未设置，则默认为csv。 | // @query.collection.format multi                               |
| schemes                 | 用空格分隔的请求的传输协议。                                                                    | // @schemes http https                                          |
| x-name                  | 扩展的键必须以x-开头，并且只能使用json值                                                        | // @x-example-key {"key": "value"}                              |

**为接口添加注释**

代码示例如下

```
// CreateUser 创建用户
// @Tags User
// @Summary 创建用户
// @Accept json
// @Produce json
// @Param env body model.User true "用户信息参数"
// @Success 200 "返回成功"
// @Failure 400 {object} model.ErrResponse "错误信息"
// @Router /v1/user [post]
func CreateUser(ctx *gin.Context) {
}
```

API接口注释如下

| 注释                 | 描述                                                                                                    |
| -------------------- | ------------------------------------------------------------------------------------------------------- |
| description          | 操作行为的详细说明。                                                                                    |
| description.markdown | 应用程序的简短描述。该描述将从名为`endpointname.md`的文件中读取。                                       |
| id                   | 用于标识操作的唯一字符串。在所有API操作中必须唯一。                                                     |
| tags                 | 每个API操作的标签列表，以逗号分隔。                                                                     |
| summary              | 该操作的简短摘要。                                                                                      |
| accept               | API可以使用的MIME类型的列表。值必须如“[Mime类型](#mime-types)”中所述。                                  |
| produce              | API可以生成的MIME类型的列表。值必须如“[Mime类型](#mime-types)”中所述。                                  |
| param                | 用空格分隔的参数。`param name`,`param type`,`data type`,`is mandatory?`,`comment` `attribute(optional)` |
| security             | 每个API操作的[安全性](#security)。                                                                      |
| success              | 以空格分隔的成功响应。`return code`,`{param type}`,`data type`,`comment`                                |
| failure              | 以空格分隔的故障响应。`return code`,`{param type}`,`data type`,`comment`                                |
| response             | 与success、failure作用相同                                                                               |
| header               | 以空格分隔的头字段。 `return code`,`{param type}`,`data type`,`comment`                                 |
| router               | 以空格分隔的路径定义。 `path`,`[httpMethod]`                                                            |
| x-name               | 扩展字段必须以`x-`开头，并且只能使用json值。                                                            |

Mime类型

`swag` 接受所有格式正确的MIME类型, 即使匹配 `*/*`。除此之外，`swag`还接受某些MIME类型的别名，如下所示：

| Alias                 | MIME Type                         |
| --------------------- | --------------------------------- |
| json                  | application/json                  |
| xml                   | text/xml                          |
| plain                 | text/plain                        |
| html                  | text/html                         |
| mpfd                  | multipart/form-data               |
| x-www-form-urlencoded | application/x-www-form-urlencoded |
| json-api              | application/vnd.api+json          |
| json-stream           | application/x-json-stream         |
| octet-stream          | application/octet-stream          |
| png                   | image/png                         |
| jpeg                  | image/jpeg                        |
| gif                   | image/gif                         |

参数类型

- query
- path
- header
- body
- formData

数据类型

- string (string)
- integer (int, uint, uint32, uint64)
- number (float32)
- boolean (bool)
- user defined struct

对模型进行注释/参数用例

```
package model

type User struct {
    // 用户id
    ID   int    `json:"id" example:"1"`
    // 用户名
    Name string `json:"name" example:"account name"`
}
```

#### 初始化

下载swag

```
go get -u github.com/swaggo/swag/cmd/swag
```

解析注释生成代码

```
swag init  pwdToMain/main.go

如果API注释没有写在main.go中，需要添加-g

swag init -g  http/api.go
```

#### 导入包


```
import (
    // route注册时需要
    swaggerFiles "github.com/swaggo/gin-swagger" // gin-swagger middleware
    ginSwagger "github.com/swaggo/files" // swagger embed files
    // 导入生成的doc
    _ "github.com/thinkmo/demo/docs
)
```

#### 运行

可以访问 /swagger/index.html 来查看生成的接口文档


### 参考

[swagger官网](swagger.io)

[swag](https://github.com/swaggo/swag)

[gin-swagger](https://github.com/swaggo/gin-swagger)