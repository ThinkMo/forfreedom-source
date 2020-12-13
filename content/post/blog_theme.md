+++
keywords = ["hugo", "theme", "comments"]
title = "博客theme修改记录"
categories = ["others"]
comments = true
clearReading = true
date = 2020-12-13T21:40:30+08:00 
showSocial = false
showPagination = true
showTags = true
showDate = true
+++


### blog theme修改记录 

之前blog theme相关修改的代码丢失了， 需要重新配置一下，顺手记录一下

博客由hugo生成，关于hugo看[这里](https://gohugo.io/)

hugo主题使用[hugo-tranquilpeak-theme](https://github.com/kakawait/hugo-tranquilpeak-theme)

#### 评论设置

hugo-tranquilpeak-theme 仅支持disqus，但对于国内来说无法访问，这里修改了相关代码，使用[来必力](https://www.livere.com/)，注册来必力，选择免费的City版本安装

删除默认的 layouts/partials/post/disqus.html 的代码，将安装代码注入即可

```
layouts/partials/post/disqus.html

<!-- 来必力City版安装代码 -->
<div id="lv-container" data-id="city" data-uid="你的uid">
<script type="text/javascript">
   (function(d, s) {
       var j, e = d.getElementsByTagName(s)[0];

       if (typeof LivereTower === 'function') { return; }

       j = d.createElement(s);
       j.src = 'https://cdn-city.livere.com/js/embed.dist.js';
       j.async = true;

       e.parentNode.insertBefore(j, e);
   })(document, 'script');
</script>
<noscript>为正常使用来必力评论功能请激活JavaScript</noscript>
</div>
<!-- City版安装代码已完成 -->
```

#### 浏览统计

浏览统计使用的是[不蒜子](https://busuanzi.ibruce.info/)

修改hugo配置文件config.toml在[params]下添加相关js

```
  [[params.customJS]]
    src = "//busuanzi.ibruce.info/busuanzi/2.3/busuanzi.pure.mini.js"
```

修改layouts/partials/footer.html在copyright下添加

```
  <div class="busuanzi-count">
    <span class="site-uv">
      <i class="fa fa-user"></i>
      <span class="busuanzi-value" id="busuanzi_value_site_uv"></span>
    </span>
    <span class="site-pv">
      <i class="fa fa-eye"></i>
      <span class="busuanzi-value" id="busuanzi_value_site_pv"></span>
    </span>
  </div>
```