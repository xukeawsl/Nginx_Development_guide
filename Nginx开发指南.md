# 介绍

## 代码布局

- auto - 构建脚本
- src
   - core - 基本类型和函数（字符串、数组、日志等）
   - event - 事件核心
      - modules - 事件通知模块（epoll、kqueue、select 等）
   - http - 核心 HTTP 模块和通用代码
      - modules - 其他 HTTP 模块
      - v2 - HTTP/2
   - mail - 邮件模块
   - os - 平台特定代码
      - unix
      - win32
   - stream - 流模块

## 包含文件
以下两个 `#include` 语句必须出现在每个 nginx 文件的开头：
```c
#include <ngx_config.h>
#include <ngx_core.h>
```
除此之外，HTTP 代码还应该包含
```c
#include <ngx_http.h>
```
Mail 代码应该包括
```c
#include <ngx_mail.h>
```
Stream 代码应该包括
```c
#include <ngx_stream.h>
```

## 整数
出于一般目的，nginx 代码使用两种整数类型（`ngx_int_t` 和 `ngx_uint_t`），它们分别是 `intptr_t` 和 `uintptr_t` 的 typedef 别名。

## 常见返回码
nginx 中的大多数函数返回以下代码：

- **NGX_OK** - 操作成功。
- **NGX_ERROR** - 操作失败。
- **NGX_AGAIN** - 操作未完成；再次调用该函数。
- **NGX_DECLINED** - 操作被拒绝，例如，因为它在配置中被禁用。这绝对不是一个错误。
- **NGX_BUSY** - 资源不可用。
- **NGX_DONE** - 操作已完成或在别处继续。也用作替代成功代码。
- **NGX_ABORT** - 函数已中止。也用作替代错误代码。

## 错误处理
`ngx_erron` 宏返回最后一个系统错误代码。它在 POSIX 平台映射到 `errno`，在 Windows 中映射到 `GetLastError()` 调用。`ngx_socket_errno` 宏返回最后一个套接字错误数字。与 `ngx_errno` 类似，它在 POSIX 平台上映射到 `errno`，在 Windows 中映射到 `WSAGetLastError()` 调用。连续多次访问 `ngx_errno` 或 `ngx_socket_errno` 的值可能会导致性能问题。如果错误值可能被多次使用，则将其存储在类型为 `ngx_err_t` 的局部变量中。要设置错误，使用 `ngx_set_errno(errno)` 和 `ngx_set_socket_errno(errno)` 宏。

可以将 `ngx_errno` 和 `ngx_socket_errno` 的值传递到日志记录函数 `ngx_log_error()` 和 `ngx_log_debugX()` ，在这种情况下，系统错误信息会被添加到日志消息中。

使用 `ngx_errno` 的示例：
```c
ngx_int_t
ngx_my_kill(ngx_pid_t pid, ngx_log_t *log, int signo)
{
    ngx_err_t err;

    if (kill(pid, signo) == -1) {
    	err = ngx_errno;

        ngx_log_error(NGX_LOG_ALERT, log, err, "kill(%P, %d) failed", pid, signo);

        if (err == NGX_ESRCH) {
        	return 2;
        }

        return 1;
    }

    return 0;
}
```

# 字符串

## 概览
对于 C 字符串，nginx 使用无符号字符类型指针 `u_char*`。

nginx 字符串类型 `ngx_str_t` 定义如下：
```c
typedef struct {
    size_t      len;
    u_char     *data;
} ngx_str_t;
```
`len` 字段保存字符串长度，`data` 保存字符串数据。保存在 `ngx_str_t` 中的字符串在 `len` 字节之后可以是也可以不是以 `\0` 字符终止的。在大多数情况下它不是。然而，在代码的某些部分（例如，在解析配置时），`ngx_str_t` 对象是以 `\0` 字符结尾的，这简化了字符串比较，并更容易将字符串传递给系统调用。

nginx 中的字符串操作在 `src/core/ngx_string.h` 中声明，其中一些是标准 C 函数的包装器：

- ngx_strcmp()
- ngx_strncmp()
- ngx_strstr()
- ngx_strlen()
- ngx_strchr()
- ngx_memcmp()
- ngx_memset()
- ngx_memcpy()
- ngx_memmove()

其他字符串函数是 nginx 特定的

- ngx_memzero() - 用零填充内存
- ngx_explicit_memzero() - 执行与 `ngx_memzero()` 相同的操作，但此调用永远不会被编译器的死码消除优化删除掉。这个函数可以用于清除密码和密钥等敏感数据。
- ngx_cpymem() - 执行与 `ngx_memcpy()` 相同的操作，但返回最终目的地址。此地址对于在行中附加多个字符串非常方便。
- ngx_movemem() - 执行与 `ngx_memmove()` 相同的操作，但返回最终目的地址。
- ngx_strlchr() - 在字符串中搜索字符，由两个指针分隔。

以下函数执行大小写转换和比较：

- ngx_tolower()
- ngx_toupper()
- ngx_strlow()
- ngx_strcasecmp()
- ngx_strncasecmp()

以下宏可以简化字符串初始化：

- ngx_string(text) - 使用 C 字符串字面量 `text` 来初始化静态 `ngx_str_t` 类型
- ngx_null_string - `ngx_str_t` 类型的静态空字符串初始化器
- ngx_str_set(str, text) - 使用 C 字符串常量 `text` 初始化 `str` 这个字符串，它是一个 `ngx_str_t *` 指针
- ngx_str_null(str) - 使用空字符串初始化 `str` 这个字符串，它是一个 `ngx_str_t *` 指针

## 格式化
以下格式化函数支持特定于 nginx 的类型：

- ngx_sprintf(buf, fmt, ...)
- ngx_snprintf(buf, max, fmt, ...)
- ngx_slprintf(buf, last, fmt, ...)
- ngx_vslprintf(buf, last, fmt, args)
- ngx_vsnprintf(buf, max, fmt, args)

这些函数支持的格式选项的完整列表在 `src/core/ngx_string.c` 中。其中一些是：

- %O - off_t
- %T - time_t
- %z - ssize_t
- %i - ngx_int_t
- %p - void *
- %V - ngx_str_t
- %s - u_char *（以 `\0` 字符终止）
- %*s - size_t + u_char *

你可以在大多数类型前加上 u，使它们成为无符号的。要将输出转换为十六进制，使用 X 或 x。

例如：
```c
u_char      buf[NGX_INT_T_LEN];
size_t      len;
ngx_uint_t  n;

/* set n here */

len = ngx_sprintf(buf, "%ui", n) - buf;
```

## 数值转换
在 nginx 中实现了几个数值转换函数。前四个函数分别将给定长度的字符串转换为指定类型的正整数。出现错误时返回 `NGX_ERROR`。

- ngx_atoi(line, n) - ngx_int_t
- ngx_atosz(line, n) - ssize_t
- ngx_atoof(line, n) - off_t
- ngx_atotm(line, n) - time_t

还有两个另外的数值转换函数。与前四个一样，它们在出错时返回 `NGX_ERROR`。

- ngx_atofp(line, n, point) - 将给定长度的定点浮点数转换为 `ngx_int_t` 类型的正整数。结果左移 `point` 小数位。数字的字符串表示形式不应超过 `points` 小数位数。例如，`ngx_atofp("10.5", 4, 2)` 返回 1050。
- ngx_hextoi(line, n) - 将正整数的十六进制表示转换为 `ngx_int_t`。

## 正则表达式
nginx 中的正则表达式接口是 [PCRE](http://www.pcre.org/) 库的包装器。对应的头文件是 `src/core/ngx_regex.h`。

要使用正则表达式进行字符串匹配，首先需要编译它，这通常在配置阶段完成。请注意，由于 PCRE 支持是可选的，所以使用接口的所有代码都必须受到 `NGX_PCRE` 宏的保护：
```c
#if (NGX_PCRE)
ngx_regex_t          *re;
ngx_regex_compile_t   rc;

u_char                errstr[NGX_MAX_CONF_ERRSTR];

ngx_str_t  value = ngx_string("message (\\d\\d\\d).*Codeword is '(?<cw>\\w+)'");

ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

rc.pattern = value;
rc.pool = cf->pool;
rc.err.len = NGX_MAX_CONF_ERRSTR;
rc.err.data = errstr;
/* rc.options can be set to NGX_REGEX_CASELESS */

if (ngx_regex_compile(&rc) != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
    return NGX_CONF_ERROR;
}

re = rc.regex;
#endif
```
成功编译后，`ngx_regex_compile_t` 结构中的 `captures` 和 `named_captures` 字段分别包含正则表达式中所有捕获和命名捕获的计数。

编译后的正则表达式可以用于匹配字符串：
```c
ngx_int_t  n;
int        captures[(1 + rc.captures) * 3];

ngx_str_t input = ngx_string("This is message 123. Codeword is 'foobar'.");

n = ngx_regex_exec(re, &input, captures, (1 + rc.captures) * 3);
if (n >= 0) {
    /* string matches expression */

} else if (n == NGX_REGEX_NO_MATCHED) {
    /* no match was found */

} else {
    /* some error */
    ngx_log_error(NGX_LOG_ALERT, log, 0, ngx_regex_exec_n " failed: %i", n);
}
```
`ngx_regex_exec()` 的参数是编译后的正则表达式 `re` 、要匹配的字符串 `input` 、一个可选的整数数组（用于保存找到的任何 `captures`）以及数组的 `size`。根据 
[PCRE API](http://www.pcre.org/original/doc/html/pcreapi.html) 的要求，s`captures` 数组的大小必须是 3 的倍数。在示例中，大小是根据捕获总数加上 1 来计算的。

如果存在匹配项，则可以按照如下方式访问捕获：
```c
u_char     *p;
size_t      size;
ngx_str_t   name, value;

/* all captures */
for (i = 0; i < n * 2; i += 2) {
    value.data = input.data + captures[i];
    value.len = captures[i + 1] - captures[i];
}

/* accessing named captures */

size = rc.name_size;
p = rc.names;

for (i = 0; i < rc.named_captures; i++, p += size) {

    /* capture name */
    name.data = &p[2];
    name.len = ngx_strlen(name.data);

    n = 2 * ((p[0] << 8) + p[1]);

    /* captured value */
    value.data = &input.data[captures[n]];
    value.len = captures[n + 1] - captures[n];
}
```
`ngx_regex_exec_array()` 函数接受 `ngx_regex_elt_t` 元素的数组（它们只是编译后的正则表达式和相关名称）、要匹配的字符串和日志。该函数将数组中的表达式应用于字符串， 直到找到匹配项或不再剩下表达式。如果匹配，返回值为 `NGX_OK`，否则返回值为 `NGX_DECLINED` ，如果出错，返回值为 `NGX_ERROR`。

## 时间
`ngx_time_t` 结构用三种不同的类型表示时间，分别是秒、毫秒和 GMT 偏移量：
```c
typedef struct {
    time_t      sec;
    ngx_uint_t  msec;
    ngx_int_t   gmtoff;
} ngx_time_t;
```
`ngx_tm_t` 结构在 UNIX 平台上是 `struct tm` 的别名，在 Windows 上是 `SYSTEMTIME` 的别名。

为了获得当前时间，通常只访问一个可用的全局变量就足够了，该变量以所需格式表示缓存的时间值。

可用的字符串表示形式包括：

- ngx_cached_err_log_time - 用于错误日志条目："1970/09/28 12:00:00"
- ngx_cached_http_log_time - 用于 HTTP 访问日志条目："28/Sep/1970:12:00:00 +0600"
- ngx_cached_syslog_time - 用于系统日志条目："Sep 28 12:00:00"
- ngx_cached_http_time - 用于 HTTP 报头："Mon, 28 Sep 1970 06:00:00 GMT"
- ngx_cached_http_log_iso8601 - ISO 8601 标准格式："1970-09-28T12:00:00+06:00"

`ngx_time()` 和 `ngx_timeofday()` 宏以秒为单位返回当前值，是访问缓存时间值的首选方式。

要显式地获取时间，使用 `ngx_gettimeofday()` ，它更新其参数（指向 `struct timeval` 的指针）。nginx 从系统调用返回事件循环时，时间总是更新的。若要立即更新时间，请调用 `ngx_time_update()` ，如果在信号处理程序上下文中更新时间，则调用 `ngx_time_sigsafe_update()`。

以下函数将 `time_t` 转换为指示的细分时间表示。每对中的第一个函数将 `time_t` 转换为 `ngx_tm_t` ，第二个函数（带有 `_libc_` 中缀）转换为 `struct tm`：

- ngx_gmtime(), ngx_libc_gmtime() - 以 UTC 表示的时间
- ngx_localtime(), ngx_libc_localtime() - 相对于当地时区表示的时间

`ngx_http_time(buf, time)` 函数返回适合在 HTTP 头中使用的字符串表示形式（例如，"Mon, 28 Sep 1970 06:00:00 GMT"）。`ngx_http_cookie_time(buf, time)` 函数返回适合 HTTP cookie 表示的字符串形式（"Thu, 31-Dec-37 23:55:55 GMT"）。

# 容器

## 数组
nginx 数组类型 `ngx_array_t` 定义如下：
```c
typedef struct {
    void        *elts;
    ngx_uint_t   nelts;
    size_t       size;
    ngx_uint_t   nalloc;
    ngx_pool_t  *pool;
} ngx_array_t;
```
数组的元素在 `elts` 字段中可用。`nelts` 字段保存元素的数量。`size` 字段保存单个元素的大小，并在初始化数组时设置。

使用 `ngx_array_create(pool, n, size)` 调用在池中创建数组，使用 `ngx_array_init(array, pool, n, size)` 调用初始化已经分配的数组对象。
```c
ngx_array_t  *a, b;

/* create an array of strings with preallocated memory for 10 elements */
a = ngx_array_create(pool, 10, sizeof(ngx_str_t));

/* initialize string array for 10 elements */
ngx_array_init(&b, pool, 10, sizeof(ngx_str_t));
```
使用以下函数向数组添加元素：

- `ngx_array_push(a)` 在数组尾部添加一个元素并返回指向它的指针
- `ngx_array_push_n(a, n)` 在数组尾部添加 n 个元素并返回指向第一个元素的指针

如果当前分配的内存量不足以容纳新元素，则分配新的内存并将现有的元素赋值到这块内存。新内存块通常是现有内存块的两倍大。
```c
s = ngx_array_push(a);
ss = ngx_array_push(&b, 3);
```

## 列表
在 nginx 中，列表是数组的序列，经过优化可以插入潜在的大量元素。`ngx_list_t` 列表类型定义如下：
```c
typedef struct {
    ngx_list_part_t  *last;
    ngx_list_part_t   part;
    size_t            size;
    ngx_uint_t        nalloc;
    ngx_pool_t       *pool;
} ngx_list_t;
```
实际元素存储在`ngx_list_part_s` 结构中，其定义如下：
```c
typedef struct ngx_list_part_s  ngx_list_part_t;

struct ngx_list_part_s {
    void             *elts;
    ngx_uint_t        nelts;
    ngx_list_part_t  *next;
};
```
使用前，必须通过调用 `ngx_list_init(list, pool, n, size)` 初始化列表或通过调用 `ngx_list_create(pool, n, size)` 创建列表。这两个函数都将单个元素的大小和每个 `ngx_list_part_s` 包含的元素数目作为参数。要遍历这些元素，请直接访问列表字段，如示例所示：
```c
ngx_str_t        *v;
ngx_uint_t        i;
ngx_list_t       *list;
ngx_list_part_t  *part;

list = ngx_list_create(pool, 100, sizeof(ngx_str_t));
if (list == NULL) { /* error */ }

/* add items to the list */

v = ngx_list_push(list);
if (v == NULL) { /* error */ }
ngx_str_set(v, "foo");

v = ngx_list_push(list);
if (v == NULL) { /* error */ }
ngx_str_set(v, "bar");

/* iterate over the list */

part = &list->part;
v = part->elts;

for (i = 0; /* void */; i++) {

    if (i >= part->nelts) {
        if (part->next == NULL) {
            break;
        }

        part = part->next;
        v = part->elts;
        i = 0;
    }

    ngx_do_smth(&v[i]);
}
```
列表主要用于 HTTP 输入/输出头。

列表不支持元素删除。但是，当需要时，可以在元素内部标记为缺失，而不实际从列表中删除。例如，要将 HTTP 输出头（存储为 `ngx_table_elt_t` 对象）标记为缺失，就设置 `ngx_table_elt_t` 的 `hash` 字段为 0。在迭代头部时，以这种方式标记的元素将显式跳过。

## 队列
在 nginx 中，队列是一个侵入式双向链表，每个节点定义如下：
```c
typedef struct ngx_queue_s  ngx_queue_t;

struct ngx_queue_s {
    ngx_queue_t  *prev;
    ngx_queue_t  *next;
};
```
队列头节点未与任何数据链接。在使用前调用 `ngx_queue_init(q)` 初始化队列头。队列支持以下操作：

- ngx_queue_insert_head(h, x), ngx_queue_insert_tail(h, x) - 插入一个新节点
- ngx_queue_remove(x) - 删除一个队列节点
- ngx_queue_split(h, q, n) - 在节点上拆分队列，返回拆分出的队列的队尾
- ngx_queue_add(h, n) - 向第一个队列中添加第二个队列
- ngx_queue_head(h), ngx_queue_last(h) - 获取第一个或最后一个队列节点
- ngx_queue_sentinel(h) - 获取队列哨兵以结束迭代
- ngx_queue_data(q, type, link) - 获取对队列节点数据结构开头的引用，考虑其中的队列字段偏移量

举个例子：
```c
typedef struct {
    ngx_str_t    value;
    ngx_queue_t  queue;
} ngx_foo_t;

ngx_foo_t    *f;
ngx_queue_t   values, *q;

ngx_queue_init(&values);

f = ngx_palloc(pool, sizeof(ngx_foo_t));
if (f == NULL) { /* error */ }
ngx_str_set(&f->value, "foo");

ngx_queue_insert_tail(&values, &f->queue);

/* insert more nodes here */

for (q = ngx_queue_head(&values);
     q != ngx_queue_sentinel(&values);
     q = ngx_queue_next(q))
{
    f = ngx_queue_data(q, ngx_foo_t, queue);

    ngx_do_smth(&f->value);
}
```

## 红黑树
`src/core/ngx_rbtree.h` 头文件提供了对红黑树的有效实现的访问。
```c
typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;

    /* custom per-tree data here */
} my_tree_t;

typedef struct {
    ngx_rbtree_node_t  rbnode;

    /* custom per-node data */
    foo_t              val;
} my_node_t;
```
要将树作为一个整体处理，你需要两个节点：根和哨兵。通常，它们被添加到自定义结构中，允许你讲数据组织到一个树中，其中叶子包含指向数据的链接或嵌入数据。

要初始化树，请执行以下操作：
```c
my_tree_t  root;

ngx_rbtree_init(&root.rbtree, &root.sentinel, insert_value_function);
```
要遍历树并插入新值，使用 "insert_value" 函数。例如，`ngx_str_rbtree_insert_value` 函数处理 `ngx_str_t` 类型。它的参数是指向插入树的根节点、要添加的新建节点和树哨兵的指针。
```c
void ngx_str_rbtree_insert_value(ngx_rbtree_node_t *temp,
                                 ngx_rbtree_node_t *node,
                                 ngx_rbtree_node_t *sentinel)
```
遍历非常简单，可以用下面的查找函数模式来演示：
```c
my_node_t *
my_rbtree_lookup(ngx_rbtree_t *rbtree, foo_t *val, uint32_t hash)
{
    ngx_int_t           rc;
    my_node_t          *n;
    ngx_rbtree_node_t  *node, *sentinel;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        n = (my_node_t *) node;

        if (hash != node->key) {
            node = (hash < node->key) ? node->left : node->right;
            continue;
        }

        rc = compare(val, node->val);

        if (rc < 0) {
            node = node->left;
            continue;
        }

        if (rc > 0) {
            node = node->right;
            continue;
        }

        return n;
    }

    return NULL;
}
```
`compare()` 函数是一个经典的比较器函数，返回小于、等于或大于零的值。为了加快查找速度并避免比较可能很大的用户对象，使用了整数散列字段。

要将节点添加到树中，请分配一个新节点，初始化它并调用 `ngx_rbtree_insert()`：
```c
my_node_t          *my_node;
ngx_rbtree_node_t  *node;

my_node = ngx_palloc(...);
init_custom_data(&my_node->val);

node = &my_node->rbnode;
node->key = create_key(my_node->val);

ngx_rbtree_insert(&root->rbtree, node);
```
要删除节点，请调用 `ngx_rbtree_delete()` 函数：
```c
ngx_rbtree_delete(&root->rbtree, node);
```

## 哈希
哈希表函数在 `src/core/ngx_hash.h` 中声明。支持精确匹配和通配符匹配。后者需要额外的设置，在下面的独立章节中进行描述。

在初始化散列表之前，你需要知道它将容纳的元素数量，以便 nginx 能够以最佳方式构建它。需要配置的两个参数是 `max_size` 和 `bucket_size` ，详见[独立文档](https://nginx.org/en/docs/hash.html)。tm通常可由用户配置。哈希初始化设置以 `ngx_hash_init_t` 类型存储，哈希本身为 `ngx_hash_t`：
```c
ngx_hash_t       foo_hash;
ngx_hash_init_t  hash;

hash.hash = &foo_hash;
hash.key = ngx_hash_key;
hash.max_size = 512;
hash.bucket_size = ngx_align(64, ngx_cacheline_size);
hash.name = "foo_hash";
hash.pool = cf->pool;
hash.temp_pool = cf->temp_pool;
```
`key` 是一个指向函数的指针，该函数从字符串创建哈希整数键。有两个通用的密钥创建函数：`ngx_hash_key(data, len)` 和 `ngx_hash_key_lc(data, len)`。后者将字符串转换为全小写字符，因此传递的字符串必须是可写的。如果不是可写的，将 `NGX_HASH_READONLY_KEY` 标志传递给函数，初始化键数组（见下文）。

哈希键存储在 `ngx_hash_keys_arrays_t` 中，通过 `ngx_hash_keys_array_init(arr, type)`初始化：第二个参数（type） 控制为哈希预分配的资源量，并且可以是 `NGX_HASH_SMALL` 或 `NGX_HASH_LARGE`。如果你希望哈希包含数千个元素，则后者是合适的。
```c
ngx_hash_keys_arrays_t  foo_keys;

foo_keys.pool = cf->pool;
foo_keys.temp_pool = cf->temp_pool;

ngx_hash_keys_array_init(&foo_keys, NGX_HASH_SMALL);
```
要将键插入哈希键数组，请使用 `ngx_hash_add_key(keys_array, key, value, flags)` 函数：
```c
ngx_str_t k1 = ngx_string("key1");
ngx_str_t k2 = ngx_string("key2");

ngx_hash_add_key(&foo_keys, &k1, &my_data_ptr_1, NGX_HASH_READONLY_KEY);
ngx_hash_add_key(&foo_keys, &k2, &my_data_ptr_2, NGX_HASH_READONLY_KEY);
```
要构建哈希表，请调用 `ngx_hash_init(hinit, key_names, nelts)` 函数：
```c
ngx_hash_init(&hash, foo_keys.keys.elts, foo_keys.keys.nelts);
```
如果 `max_size` 或 `bucket_size` 参数不够大，则函数失败。

构建哈希时，使用 `ngx_hash_find(hash, key, name, len)` 函数查找元素：
```c
my_data_t   *data;
ngx_uint_t   key;

key = ngx_hash_key(k1.data, k1.len);

data = ngx_hash_find(&foo_hash, key, k1.data, k1.len);
if (data == NULL) {
    /* key not found */
}
```

## 通配符匹配
要创建一个支持通配符的哈希，请使用 `ngx_hash_combined_t` 类型。它包括上面描述的哈希类型，并具有两个额外的键数组：`dns_wc_head` 和 `dns_wc_tail` 。基本属性的初始化类似于常规哈希：
```c
ngx_hash_init_t      hash
ngx_hash_combined_t  foo_hash;

hash.hash = &foo_hash.hash;
hash.key = ...;
```
可以使用 `NGX_HASH_WILDCARD_KEY` 标志添加通配符键：
```c
/* k1 = ".example.org"; */
/* k2 = "foo.*";        */
ngx_hash_add_key(&foo_keys, &k1, &data1, NGX_HASH_WILDCARD_KEY);
ngx_hash_add_key(&foo_keys, &k2, &data2, NGX_HASH_WILDCARD_KEY);
```
该函数识别通配符并将键添加到相应的数组中。有关通配符语法和匹配算法的描述，请参阅 [map](https://nginx.org/en/docs/http/ngx_http_map_module.html#map) 模块文档。

根据添加的键的内容，你可能需要初始化最多三个键数组：一个用于精确匹配（如上所述），另外两个用于从字符串的头部或尾部开始匹配：
```c
if (foo_keys.dns_wc_head.nelts) {

    ngx_qsort(foo_keys.dns_wc_head.elts,
              (size_t) foo_keys.dns_wc_head.nelts,
              sizeof(ngx_hash_key_t),
              cmp_dns_wildcards);

    hash.hash = NULL;
    hash.temp_pool = pool;

    if (ngx_hash_wildcard_init(&hash, foo_keys.dns_wc_head.elts,
                               foo_keys.dns_wc_head.nelts)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    foo_hash.wc_head = (ngx_hash_wildcard_t *) hash.hash;
}
```
keys 数组需要排序，并且初始化结果必须添加到组合哈希中。`dns_wc_tail` 数组的初始化也是类似的。

组合哈希中的查找由 `ngx_hash_find_combined(chash, key, name, len)` 处理：
```c
/* key = "bar.example.org"; — will match ".example.org" */
/* key = "foo.example.com"; — will match "foo.*"        */

hkey = ngx_hash_key(key.data, key.len);
res = ngx_hash_find_combined(&foo_hash, hkey, key.data, key.len);
```

# 内存管理

## 堆
要从系统堆中分配内存，请使用以下函数：

- ngx_alloc(size, log) - 从系统堆中分配内存。这是一个 `malloc()` 的包装器，支持日志记录。分配错误和调试信息记录到 `log`。
- ngx_calloc(size, log) - 像 `ngx_alloc()` 一样从系统堆中分配内存，但在分配后用零填充内存。
- ngx_memalign(alignment, size, log) - 从系统堆中分配对齐的内存。这是在提供该功能的平台上对 `posix_memalign()` 的包装器。否则，实现将回退到 `ngx_alloc()` ，它提供了最大程度的对齐。
- ngx_free(p) - 释放分配的内存。这是一个 `free()` 的包装器。

## 池
大多数 nginx 分配都是在池中完成的。在 nginx 池中分配的内存会在池被销毁时自动释放。这提供了良好的分配性能，并使内存控制变得容易。

池在内部分配连续内存块中的对象。一旦某个块满了，则会分配一个新的块并将其添加到池内存块列表中。当请求的分配太大而不能放入块时，请求被转发到系统分配器，返回的指针被存储在池中以进一步解除分配。

nginx 池的类型是 `ngx_pool_t`。支持以下操作：

- ngx_create_pool(size, log) - 创建具有指定块大小的池。返回的池对象也会在池中分配。`size` 应该至少是 `NGX_MIN_POOL_SIZE` 和 `NGX_POOL_ALIGNMENT` 的倍数。
- ngx_destroy_pool(pool) - 释放所有池内存，包括池对象本身。
- ngx_palloc(pool, size) - 从指定池中分配对齐的内存。
- ngx_pcalloc(pool, size) - 从指定的池中分配对齐的内存，并用零填充它。
- ngx_pnalloc(pool, size) - 从指定池中分配未对齐的内存。主要用于分配字符串。
- ngx_pfree(pool, p) - 释放以前在指定池中分配的内存。只有通过系统分配器分配的内存才能被释放。
```c
u_char      *p;
ngx_str_t   *s;
ngx_pool_t  *pool;

pool = ngx_create_pool(1024, log);
if (pool == NULL) { /* error */ }

s = ngx_palloc(pool, sizeof(ngx_str_t));
if (s == NULL) { /* error */ }
ngx_str_set(s, "foo");

p = ngx_pnalloc(pool, 3);
if (p == NULL) { /* error */ }
ngx_memcpy(p, "foo", 3);
```
链节（`ngx_chain_t`）在 nginx 中被积极使用，所以 nginx 池实现提供了一种重用它们的方法。`ngx_pool_t` 的 `chain` 字段保留了一个预先分配的链路的列表以供重用。为了有效地分配池中的链节，请使用 `ngx_alloc_chain_link(pool)` 函数。此函数在池列表中查找空闲链，如果池列表为空，则分配新链。要释放链，请调用 `ngx_free_chain(pool, cl)` 函数。

cleanup 句柄可以在池中注册。一个 cleanup 句柄是一个代用参数的回调函数，当池被销毁时调用该函数。池通常与特定的 nginx 对象（如 HTTP 请求）绑定，并在对象生命周期结束时销毁。注册 cleanup 是释放资源、关闭文件描述符或对与主对象关联的共享数据进行最终调整的便利方法。

要注册池的 cleanup，请调用 `ngx_pool_cleanup_add(pool, size)`，它返回一个要由调用者填写的 `ngx_pool_cleanup_t` 指针。使用 `size` 参数为 cleanup 句柄分配上下文。
```c
ngx_pool_cleanup_t  *cln;

cln = ngx_pool_cleanup_add(pool, 0);
if (cln == NULL) { /* error */ }

cln->handler = ngx_my_cleanup;
cln->data = "foo";

...

static void
ngx_my_cleanup(void *data)
{
    u_char  *msg = data;

    ngx_do_smth(msg);
}
```

## 共享内存
nginx 使用共享内存在进程之间共享公共数据。`ngx_shared_memory_add(cf, name, size, tag)` 函数添加新的共享内存条目 `ngx_shm_zone_t` 到 cycle。该函数接受共享区域的 `name` 和 `size` 。每个共享区域必须有唯一的名称。如果已经存在具有所提供的 `name` 和 `tag` 的共享区域条目，则重用现有区域条目。如果同名的现有条目具有不同的标记，则函数将失败并显示错误。通常，模块结构的地址被传递为 `tag`，使得可以在一个 nginx 模块中按名称重用共享区域。

共享内存条目结构 `ngx_shm_zone_t` 具有以下字段：

- init - 初始化回调，调用后共享区域被映射到实际内存
- data - 数据上下文，用于将任意数据传递给 `init` 回调
- noreuse - 禁止从旧 cycle 复用共享区域的标志
- tag - 共享区域标签
- shm - 类型 `ngx_shm_t` 的平台特定对象，至少具有以下字段：
   - addr - 映射的共享内存地址，初始为 NULL
   - size - 共享内存大小
   - name - 共享内存名称
   - log - 共享内存日志
   - exists - 指示共享内存是从主进程继承的标志（特定于 Windows）

解析配置后，共享区域条目映射到 `ngx_init_cycle()` 中的实际内存。在 POSIX 系统上，`mmap()` 系统调用用于创建共享匿名映射。在 Windows 上，使用 `CreateFileMapping()/MapViewOfFileEx()` 对。

对于共享内存的分配，nginx 提供了 slab 池 `ngx_slab_pool_t` 类型。在每个 nginx 共享区域中自动创建一个用于分配内存的 slab 池。池位于共享区域的开头，可以通过表达式 `(ngx_slab_pool_t *) shm_zone->shm.addr` 访问。要在共享区域中分配内存，请调用 `ngx_slab_alloc(pool, size)` 或 `ngx_slab_calloc(pool, size)`。要释放内存，请调用 `ngx_slab_free(pool, p)`。

slab 池将所有共享区域划分为页。每个页用于分配相同大小的对象。指定的大小必须是 2 的幂，并且大于 8 字节的最小大小。不符合要求的值四舍五入。每个页的位掩码跟踪哪些块在使用中以及哪些块可供分配。对于大于半页（通常为 2048 字节）的大小，一次分配整个页。

要从并发访问中保护共享内存中的数据，请使用 `ngx_slab_pool_t` 的 `mutex` 互斥锁字段。在分配和释放内存时，slab 池最常用的是互斥体，但它也可以用来保护共享区域中分配的任何其他用户数据结构。要锁定或解锁互斥锁，请分别调用 `ngx_shmtx_lock(&shpool->mutex)` 或 `ngx_shmtx_unlock(&shpool->mutex)`。
```c
ngx_str_t        name;
ngx_foo_ctx_t   *ctx;
ngx_shm_zone_t  *shm_zone;

ngx_str_set(&name, "foo");

/* allocate shared zone context */
ctx = ngx_pcalloc(cf->pool, sizeof(ngx_foo_ctx_t));
if (ctx == NULL) {
    /* error */
}

/* add an entry for 64k shared zone */
shm_zone = ngx_shared_memory_add(cf, &name, 65536, &ngx_foo_module);
if (shm_zone == NULL) {
    /* error */
}

/* register init callback and context */
shm_zone->init = ngx_foo_init_zone;
shm_zone->data = ctx;


...


static ngx_int_t
ngx_foo_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_foo_ctx_t  *octx = data;

    size_t            len;
    ngx_foo_ctx_t    *ctx;
    ngx_slab_pool_t  *shpool;

    value = shm_zone->data;

    if (octx) {
        /* reusing a shared zone from old cycle */
        ctx->value = octx->value;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        /* initialize shared zone context in Windows nginx worker */
        ctx->value = shpool->data;
        return NGX_OK;
    }

    /* initialize shared zone */

    ctx->value = ngx_slab_alloc(shpool, sizeof(ngx_uint_t));
    if (ctx->value == NULL) {
        return NGX_ERROR;
    }

    shpool->data = ctx->value;

    return NGX_OK;
}
```

## 日志
nginx 使用 `ngx_log_t` 对象进行日志记录。nginx logger 支持多种类型的输出：

- stderr - 记录到标准错误（stderr）
- file - 记录到文件
- syslog - 记录到系统日志
- memory - 处于开发目的记录到内存；稍后可以使用调试器访问内存

日志示例可以是一条日志链，通过 `next` 字段相互链接。在这种情况下，每条消息都被写入链中的所有日志对象。

对于每个日志对象，一个严重级别控制哪些消息被写入日志（仅记录分配给该级别或更高级别的事件）。支持以下严重级别：

- **NGX_LOG_EMERG**
- **NGX_LOG_ALERT**
- **NGX_LOG_CRIT**
- **NGX_LOG_ERR**
- **NGX_LOG_WARN**
- **NGX_LOG_NOTICE**
- **NGX_LOG_INFO**
- **NGX_LOG_DEBUG**

对于调试日志，还将检查调试掩码。调试掩码有：

- **NGX_LOG_DEBUG_CORE**
- **NGX_LOG_DEBUG_ALLOC**
- **NGX_LOG_DEBUG_MUTEX**
- **NGX_LOG_DEBUG_EVENT**
- **NGX_LOG_DEBUG_HTTP**
- **NGX_LOG_DEBUG_MAIL**
- **NGX_LOG_DEBUG_STREAM**

通常情况下，日志是由现有的 nginx 代码从 `error_log` 指令创建的，几乎在周期、配置、客户端连接和其他对象的每个处理阶段都可用。

Nginx 提供了以下日志宏：

- ngx_log_error(level, log, err, fmt, ...) - 错误日志
- ngx_log_debug0(level1, log, err, fmt), ngx_log_debug1(level, log, err, fmt, arg1) 等 - 调试日志最多支持八个格式化参数

日志消息在栈上大小为 `NGX_MAX_ERROR_STR` （当前为 2048 字节）的缓冲区中格式化。该消息的前面带有严重级别、进程 ID（PID）、连接 ID（存储在 `log->connection` 中）和系统错误内容。对于非调试消息，还调用 `log->handler`，以便在日志消息中预先添加更具体的信息。HTTP 模块将 `ngx_http_log_error()` 函数设置为日志处理器，用于记录客户端和服务器地址、当前操作（存在在 `log->action` 中）、客户端请求行、服务器名称等。
```c
/* specify what is currently done */
log->action = "sending mp4 to client";

/* error and debug log */
ngx_log_error(NGX_LOG_INFO, c->log, 0, "client prematurely closed connection");

ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
               "mp4 start:%ui, length:%ui", mp4->start, mp4->length);
```
上面的示例会产生如下日志条目：
```
2016/09/16 22:08:52 [info] 17445#0: *1 client prematurely closed connection while sending mp4 to client, client: 127.0.0.1, server: , request: "GET /file.mp4 HTTP/1.1"
2016/09/16 23:28:33 [debug] 22140#0: *1 mp4 start:0, length:10000
```

## Cycle
cycle 对象存储从特定配置创建的 nginx 运行时上下文。类型为 `ngx_cycle_t`。当前 cycle 由 `ngx_cycle` 全局变量引用，并由 nginx worker 在启动时继承。每次重新加载 nginx 配置时，都会从新 nginx 配置中创建一个新的 cycle；通常在成功创建新 cycle 之后删除旧 cycle。

一个 cycle 由 `ngx_init_cycle()` 函数创建，该函数将上一个 cycle 作为其参数。该函数定位上一个 cycle 的配置文件，并从上一个 cycle 继承尽可能多的资源。一个名为 "init_cycle”的占位 cycle 在 nginx 启动时创建，然后被从配置构建的实际 cycle 替换。

cycle 的成员包括：

- pool - cycle 池。用于创建每个新 cycle。
- log - cycle 日志。最初继承自旧 cycle，在读取配置后将其设置为指向 `new_log`。
- new_log - cycle 日志，由配置创建。它受到根作用域 `error_log` 指令的影响。
- connections, connection_n - 类型为 `ngx_connection_t` 的连接数组，由事件模块在初始化每个 nginx worker 时创建。nginx 配置中的 `worker_connections` 指令设置连接数 `connection_n`。
- free_connections，free_connection_n - 当前可用连接的列表和数量。如果没有可用的连接，nginx worker 拒绝接受新客户端或连接到上游服务器。
- files，files_n - 用于将文件描述符映射到 nginx 连接的数组。事件模块使用此映射，具有 `NGX_USE_FD_EVENT` 标志（目前是 `poll` 和 `devpoll`）。
- conf_ctx - 核心模块配置数组。这些配置是在读取 nginx 配置文件时创建和填充的。
- modules, modules_n - 由当前配置加载的类型 `ngx_module_t` 的模块队列，包括静态和动态。
- listening - 类型 `ngx_listening_t` 的监听对象数组。监听对象通常由调用 `ngx_create_listening()` 函数的不同模块的 `listen` 指令添加。监听套接字是基于监听对象创建的。
- paths - 类型 `ngx_path_t` 的路径数组。路径是通过从将要在某些目录上操作的模块调用函数 `ngx_add_path()` 来添加的。这些目录是 nginx 在读取配置后创建的，如果缺少的话。此外，可以为每个路径添加两个处理程序：
   - path loader - 在启动或重新加载 nginx 后 60 秒内只执行一次。通常，加载器读取目录并将数据存储在 nginx 共享内存中。处理程序是从专用的 nginx 进程 "nginx cache loader" 调用的。
   - path manager - 定期执行。通常，管理器会从目录中删除旧文件，并更新 nginx 内存以反映更改。处理程序是从专用的 "nginx cache manager" 进程调用的。
- open_files - 类型 `ngx_open_file_t` 的打开文件对象的列表，这些对象是通过调用函数 `ngx_conf_open_file()` 创建的。目前，nginx 使用这种打开的文件进行日志记录。读取配置后，nginx 打开 `open_files` 列表中的所有文件，并将每个文件描述符存储在对象的 `fd` 字段中。文件将以追加模式打开，如果丢失，则创建文件。nginx worker 在接收到重新打开的信号后重新打开列表中的文件（通常是 `USR1`）。在这种情况下，`fd` 字段中的描述符被改变为新值。
- shared_memory - 共享内存区域的列表，每个共享内存区域通过调用 `ngx_shared_memory_add()` 函数添加。共享内存区域映射到所有 nginx 进程中的相同地址范围，用于共享公共数据，例如 HTTP 缓冲内存树。

## 缓冲区
对于输入/输出操作，nginx 提供了缓冲区类型 `ngx_buf_t`。通常，它用于保存要写入目标或从源读取的数据。缓冲区可以引用内存或文件中的数据，而且缓冲区可以同时引用两者。用于缓冲区的内存被单独分配，并且与缓冲区结构 `ngx_buf_t` 无关。

`ngx_buf_t` 结构具有以下字段：

- start, end - 分配给缓冲区的内存块的边界。
- pos, last - 内存缓冲区的边界；通常是 `start..end` 的子范围。
- file_pos, file_last - 文件缓冲区的边界，表示为距离文件开头的偏移量。
- tag - 用于区分缓冲区的唯一值；由不同的 nginx 模块创建，通常用于缓冲区复用。
- file - 文件对象。
- temporary - 指示缓冲区引用可写内存的标志。
- memory - 指示缓冲区引用只读内存的标志。
- in_file - 指示缓冲区引用文件中的数据的标志。
- flush - 指示缓冲区之前的所有数据需要被刷新的标志。
- recycled - 表示缓冲区可重用且需要尽快消耗的标志。
- sync - 指示缓冲区不携带数据或特殊信号的标志，如 `flush` 或 `last_buf`。默认情况下，nginx 将此类缓冲区视为错误条件，但此标志告诉 nginx 跳过错误检查。
- last_buf - 指示缓冲区是输出中最后一个的标志。
- last_in_chain - 指示在请求或子请求中没有更多的数据缓冲区的标志。
- shadow - 引用与当前缓冲区相关的另外一个缓冲区（"影子"），通常是在缓冲区使用影子中的数据的意义上。当缓冲区被消耗时，影子缓冲区通常也被标记为已消耗。
- last_shadow - 指示缓冲区是引用特定影子缓冲区的最后一个缓冲区的标志。
- temp_file - 指示缓冲区位于临时文件中的标志。

对于输入和输出操作，缓冲区链接在链中。链是类型 `ngx_chain_t` 的链节序列，定义如下：
```c
typedef struct ngx_chain_s  ngx_chain_t;

struct ngx_chain_s {
    ngx_buf_t    *buf;
    ngx_chain_t  *next;
};
```
每个链节保留对其缓冲区的引用和对下一个链节的引用。

使用缓冲区和链的示例：
```c
ngx_chain_t *
ngx_get_my_chain(ngx_pool_t *pool)
{
    ngx_buf_t    *b;
    ngx_chain_t  *out, *cl, **ll;

    /* first buf */
    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) { /* error */ }

    b = ngx_calloc_buf(pool);
    if (b == NULL) { /* error */ }

    b->start = (u_char *) "foo";
    b->pos = b->start;
    b->end = b->start + 3;
    b->last = b->end;
    b->memory = 1; /* read-only memory */

    cl->buf = b;
    out = cl;
    ll = &cl->next;

    /* second buf */
    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) { /* error */ }

    b = ngx_create_temp_buf(pool, 3);
    if (b == NULL) { /* error */ }

    b->last = ngx_cpymem(b->last, "foo", 3);

    cl->buf = b;
    cl->next = NULL;
    *ll = cl;

    return out;
}
```

# 网络

## 连接
连接类型 `ngx_connection_t` 是套接字描述符的包装器。它包括以下字段：

- fd - 套接字描述符。
- data - 任意连接上下文。通常，它是一个指向建立在连接之上的更高级别对象的指针，例如 HTTP 请求或 Stream 会话。
- read, write - 连接的读写事件。
- recv, send, recv_chain, send_chain - 连接的 I/O 操作。
- pool - 连接的池。
- log - 连接日志。
- sockaddr, socklen, addr_text - 二进制和文本形式的远程套接字地址。
- local_sockaddr, local_socklen - 二进制形式的本地套接字地址。最初，这些字段是空的。使用 `ngx_connection_local_sockaddr()` 函数获取本地套接字地址。
- proxy_protocol_addr, proxy_protocol_port - 代理协议客户端地址和端口（如果连接启用的代理协议）。
- ssl - 连接的 SSL 上下文。
- reusable - 指示连接处于使其有资格重新使用的状态的标志。
- close - 表示连接正在被重用并且需要关闭的标志。

nginx 连接可以透明地封装 SSL 层。在这种情况下，连接的 `ssl` 字段持有一个指向 `ngx_ssl_connection_t` 结构的指针，保存连接的所有 SSL 相关数据，包括 `SSL_CTX` 和 `SSL`。`recv`、`send`、`recv_chain` 和 `send_chain` 处理程序也设置为支持 SSL 的函数。

nginx 配置中的 `worker_connections` 指令限制了每个 nginx worker 的连接数。所有的连接结构在 worker 启动时被预先创建，并存储在 cycle 对象的 `connections` 字段中。要检索连接结构，请使用 `ngx_get_connection(s, log)` 函数。它接受一个套接字描述符作为它的 `s` 参数，它需要包装在一个连接结构中。

由于每个 worker 的连接数是有限的，nginx 提供了一种获取当前正在使用的连接的方法。要启用或禁用连接的重用，请调用 `ngx_reusable_connection(c, reusable)` 函数。调用 `ngx_reusable_connection(c, 1)` 设置连接结构中的 `reuse` 标志，并将连接插入 cycle 的 `reusable_connections_queue` 中。当 `ngx_get_connection()` 发现 cycle 的 `free_connections` 列表中没有可用的连接时，它调用 `ngx_drain_connection()` 释放特定数量的可用连接。对于每个这样的连接，设置 `close` 标志并调用其读取处理程序，该处理程序通过调用 `ngx_close_connection(c)` 释放连接并使其可供重用。调用 `ngx_reusable_connection(c, 0)` 时连接可以退出重用状态。HTTP 客户端连接是 nginx 中可重用连接的例子；它们被标记为可重用，直到客户端接收到第一个请求字节。

## 事件
nginx 中的事件对象 `ngx_event_t` 提供了一个通知特定事件发生的机制。

`ngx_event_t` 中的字段包括：

- data - 事件处理程序中使用的任意事件上下文，通常作为指向与事件相关的连接的指针。
- handler - 事件发生时调用的回调函数。
- write - 指示写入事件的标志。没有标志表示读取事件。
- active - 指示事件注册用于接收 I/O 通知的标志，通常来自通知机制，如 `epoll`、`kqueue`、`poll`。
- ready - 指示事件已收到 I/O 通知的标志。
- delayed - 指示 I/O 由于速率限制而延迟的标志。
- timer - 用于将事件插入定时器树的红黑树节点。
- timer_set - 指示事件计时器已设置且尚未到期的标志。
- timedout - 指示事件计时器已到期的标志。
- eof - 表示读取数据时发生 EOF 的标志。
- pending_eof - 指示 EOF 在套接字上挂起，即使在它之前可能有一些可用的数据。标志通过 **EPOLLRDHUP** `epoll` 事件或 **EV_EOF** `kqueue` 标志传递。
- error - 指示在读取（对于读取事件）或写入（对于写入事件）期间发生错误的标志。
- cancelable - 定时器事件标志，指示在关闭工作进程时应忽略该事件。正常工作进程关闭将延迟到没有计划的不可取消的计时器事件。
- posted - 指示事件被发送到队列的标志。
- queue - 用于将事件发布到队列的队列节点。

## I/O 事件
调用 `ngx_get_connection()` 函数获得的每个连接都有两个附加事件 `c->read` 和 `c->write`，用于接收套接字准备好读取的通知。所有这些事件都在边缘触发模式下运行，这意味着它们仅在套接字状态发生更改时触发通知。例如，在套接字上执行部分读取不会时 nginx 发送重复的读取通知，直到更多数据到达套接字。即使底层 I/O 通知机制本质上是水平触发（`poll`、`select` 等），nginx 也会将通知转换为边缘触发。为了使 nginx 事件通知在不同平台上的所有通知系统中保持一致。函数 `ngx_handle_read_event(rev, flags)` 和 `ngx_handle_write_event(wev, lowat)` 必须在处理 I/O 套接字通知或调用该套接字上的任何 I/O 函数之后调用。通常，函数在每个读或写事件处理程序结束时被调用一次。

## 计时器事件
可以将事件设置为在超时到期时发送通知。事件使用的计时器以自某个过去的未指定点以来的毫秒数计数，被截断为 `ngx_msec_t` 类型。可以从 `ngx_current_msec` 变量中获取其当前值。

函数 `ngx_add_timer(ev, timer)` 为事件设置超时，`ngx_del_timer(ev)` 删除先前设置的超时。全局超时红黑树 `ngx_event_timer_rbtree` 存储当前设置的所有超时。树中的键类型为 `ngx_msec_t`，是事件发生的时间。树结构支持快速插入和删除操作，以及访问最近的超时，nginx 使用它来找出等待 I/O 事件和过期事件的时间。

## 提交事件
事件可以被提交，这意味着它的处理程序将在当前事件循环迭代中的某个时间点被调用。发布事件是简化代码和避免堆栈溢出的一个很好的实践。发布的事件保存在发布队列中。`ngx_post_event(ev, q)` 宏将事件 `ev` 发布到队列 `q`。`ngx_delete_posted_event(ev)` 宏将事件 `ev` 从它当前发布的队列中删除。通常情况下，事件被发送到 `ngx_posted_events` 队列，该队列在事件循环的后期处理-在所有 I/O 和计时器事件都已经处理完毕之后。调用函数 `ngx_event_process_posted()` 来处理事件队列。它调用事件处理程序，直到队列不为空为止。这意味着已发布事件处理程序可以发布更多事件以在当前事件循环中迭代处理。

举个例子：
```c
void
ngx_my_connection_read(ngx_connection_t *c)
{
    ngx_event_t  *rev;

    rev = c->read;

    ngx_add_timer(rev, 1000);

    rev->handler = ngx_my_read_handler;

    ngx_my_read(rev);
}


void
ngx_my_read_handler(ngx_event_t *rev)
{
    ssize_t            n;
    ngx_connection_t  *c;
    u_char             buf[256];

    if (rev->timedout) { /* timeout expired */ }

    c = rev->data;

    while (rev->ready) {
        n = c->recv(c, buf, sizeof(buf));

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR) { /* error */ }

        /* process buf */
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) { /* error */ }
}
```

## 事件循环
除了 nginx 主进程，所有 nginx 进程都做 I/O，因此有一个事件循环。（nginx 主进程将大部分时间花在 `sigsuspend()` 调用中等待信号到达。）nginx 事件循环在 `ngx_process_events_and_timers()` 函数中实现，该函数被反复调用，直到进程退出。

事件循环具有以下阶段：

- 通过调用 `ngx_event_find_timer()` 查找最接近到期的超时。此函数在计时器树中查找最左边的节点，并返回节点到期之前的毫秒数。
- 通过调用特定于事件通知机制的处理程序来处理 I/O 事件，由 nginx 配置选择。此处理程序等待至少一个 I/O 事件发生，但仅在下一个超时到期之前。当读取或写入事件发生时，`ready` 标志被设置并调用事件的处理程序。对于 Linux，通常使用 `ngx_epoll_process_events()` 处理程序，它调用 `epoll_wait()` 来等待 I/O 事件。
- 通过调用 `ngx_event_expire_timers()` 使计时器过期。定时器树从最左边的元素向右迭代，直到找到未过期的超时。对于每个过期节点，`timedout` 事件标志被设置，`timer_set` 标志被重置，并且事件处理程序被调用。
- 调用 `ngx_event_process_posted()` 处理已发布事件。该函数重复地从发布的事件队列中移除第一个元素，并调用该元素的处理程序，直到队列为空。

所有 nginx 进程也处理信号。信号处理程序只设置在 `ngx_process_events_and_timers()` 调用后检查的全局变量。

## 进程
nginx 中有几种类型的进程。进程的类型保存在 `ngx_process` 全局变量中，是以下类型之一：

- **NGX_PROCESS_MASTER** - master 进程读取 NGINX 配置，创建 cycle，启动和控制子进程。它不执行任何 I/O，只响应信号。其 cycle 功能为 `ngx_master_process_cycle()`。
- **NGX_PROCESS_WORKER** - worker 进程，处理客户端连接。它由主进程启动，并响应其信号和通道命令。其 cycle 功能为 `ngx_worker_process_cycle()`。可以有多个工作进程，通过 `worker_processes` 指令配置。
- **NGX_PROCESS_SINGLE** - 单个进程，仅存在于 `master_process off` 模式下，并且是该模式下运行的唯一进程。它创建 cycle（就像 master 进程那样）并处理客户端连接（就像 worker 进程那样）。其 cycle 功能为 `ngx_single_process_cycle()`。
- **NGX_PROCESS_HELPER** - helper 进程，目前有两种类型：cache manager 和 cache loader。两者的 cycle 功能均为 `ngx_cache_manager_process_cycle()`。

nginx 进程处理以下信号：

- **NGX_SHUTDOWN_SIGNAL**（大多数系统上是 `SIGQUIT`）- 优雅关闭。在接收到该信号时，主进程向所有子进程发送关闭信号。当没有子进程剩余时，主进程将销毁 cycle 池并退出。当一个工作进程接收到这个信号时，它关闭所有的监听套接字并等待，直到没有不可取消的事件被调度，然后销毁循环池并退出。当 cache manager 和 cache loader 进程接收到这个信号时，它立即退出。`ngx_quit` 变量在进程接收到该信号时被设置为 1，并且在处理后立即复位。当 worker 进程处于关闭状态时，`ngx_exiting` 变量被设置为 1。
- **NGX_TERMINATE_SIGNAL**（大多数系统上是 `SIGTERM`）- 终止。在接收到该信号时，主进程向所有子进程发送终止信号。如果一个子进程在 1 秒内没有退出，则主进程发送 `SIGKILL` 信号来杀死它。当没有子进程留下时，主进程销毁 cycle 池并退出。当 worker 进程、cache manager 进程或 cache loader 进程接收到该信号时，它会销毁 cycle 池并退出。当接收到该信号时，变量 `ngx_terminate` 被设置为 1。
- **NGX_NOACCEPT_SIGNAL**（大多数系统上是 `SIGWINCH`）- 关闭所有 worker 和 helper 进程。在接收到该信号时，master 进程关闭其子进程。如果之前启动的新 nginx 二进制文件退出，则旧 master 的子进程将再次启动。当一个 worker 进程接收到这个信号时，它会以 `debug_points` 指令设置的调试模式关闭。
- **NGX_RECONFIGURE_SIGNAL**（大多数系统上是 `SIGHUP`）- 重新配置。在接收到该信号时，主进程重新读取配置并基于它创建新的 cycle。如果成功创建了新 cycle，则删除旧 cycle 并启动新的子进程。同时，旧子进程接收 **NGX_SHUTDOWN_SIGNAL** 信号。在单进程模式下，nginx 创建一个新的 cycle，但保留旧的 cycle，直到不再有与其绑定的活动连接的客户端。worker 进程和 helper 进程忽略此信号。
- **NGX_REOPEN_SIGNAL**（大多数系统上是 `SIGUSR1`）- 重新打开文件。主进程将此信号发送给工作进程，工作进程重新打开与 cycle 相关的所有 `open_files`。
- **NGX_CHANGEBIN_SIGNAL**（大多数系统上是 `SIGUSR2`）- 更改 nginx 二进制文件。master 进程启动一个新的 nginx 二进制文件，并传入所有监听套接字的列表。在 "NGINX" 环境变量中传递的文本格式列表用分号分隔的描述符编号组成。新的 nginx 二进制文件读取 "NGINX" 变量，并将套接字添加到其 init cycle 中。其他进程忽略此信号。

虽然所有 nginx worker 进程都能够接收并正确处理 POSIX 信号，但主进程并不使用标准的 `kill()` 系统调用来将信号传递给 worker 和 helper。相反，nginx 使用进程间套接字对，允许在所有 nginx 进程之间发送消息。然而，目前，消息仅从主节点发送到子节点。这些信息携带标准信号。

## 线程
可以将任务卸载到单独的线程中，否则这些任务将阻塞 nginx worker 进程。例如，nginx 可以配置为使用线程执行文件 I/O。另一个用例是一个没有异步接口的库，因此不能正常使用 nginx。请记住，线程接口是现有异步处理客户端连接的辅助工具，绝不意味着替代方式。

为了处理同步，以下是 `pthreads` 原语上的包装器：

- typdef pthread_mutex_t ngx_thread_mutex_t;
   - ngx_int_t    ngx_thread_mutex_create(ngx_thread_mutex_t *mtx, ngx_log_t *log);
   - ngx_int_t    ngx_thread_mutex_destroy(ngx_thread_mutex_t *mtx, ngx_log_t *log);
   - ngx_int_t ngx_thread_mutex_lock(ngx_thread_mutex_t *mtx, ngx_log_t *log);
   - ngx_int_t ngx_thread_mutex_unlock(ngx_thread_mutex_t *mtx, ngx_log_t *log);
- typedef pthread_cond_t ngx_thread_cond_t;
   - ngx_int_t ngx_thread_cond_create(ngx_thread_cond_t *cond, ngx_log_t *log);
   - ngx_int_t ngx_thread_cond_destroy(ngx_thread_cond_t *cond, ngx_log_t *log);
   - ngx_int_t ngx_thread_cond_signal(ngx_thread_cond_t *cond, ngx_log_t *log);
   - ngx_int_t ngx_thread_cond_wait(ngx_thread_cond_t *cond, ngx_thread_mutex_t *mtx, ngx_log_t *log);

nginx 不是为每个线程任务创建一个新线程，而是实现了 [thread_pool](https://nginx.org/en/docs/ngx_core_module.html#thread_pool) 策略。多个线程池可以被配置用于不同的目的（例如，在不同组的磁盘上执行 I/O）。每个线程池都在启动时创建，并且包含处理任务队列的有限数量的线程。当任务完成时，将调用预定义的完成处理程序。

`src/core/ngx_thread_pool.h` 头文件包含相关定义：
```c
struct ngx_thread_task_s {
    ngx_thread_task_t   *next;
    ngx_uint_t           id;
    void                *ctx;
    void               (*handler)(void *data, ngx_log_t *log);
    ngx_event_t          event;
};

typedef struct ngx_thread_pool_s  ngx_thread_pool_t;

ngx_thread_pool_t *ngx_thread_pool_add(ngx_conf_t *cf, ngx_str_t *name);
ngx_thread_pool_t *ngx_thread_pool_get(ngx_cycle_t *cycle, ngx_str_t *name);

ngx_thread_task_t *ngx_thread_task_alloc(ngx_pool_t *pool, size_t size);
ngx_int_t ngx_thread_task_post(ngx_thread_pool_t *tp, ngx_thread_task_t *task);
```
在配置时，希望使用线程的模块必须通过调用 `ngx_thread_pool_add(cf, name)` 来获得对线程池的引用，这要么创建一个具有给定 `name` 的新线程池，要么返回一个具有该名称的池的引用（如果它已经存在）。

要在运行时将 `task` 添加到指定线程池 `tp` 的队列中，请使用 `ngx_thread_task_post(tp, task)` 函数。要在线程中执行函数，请传递参数并使用 `ngx_thread_task_t` 结构设置完成处理程序：
```c
typedef struct {
    int    foo;
} my_thread_ctx_t;


static void
my_thread_func(void *data, ngx_log_t *log)
{
    my_thread_ctx_t *ctx = data;

    /* this function is executed in a separate thread */
}


static void
my_thread_completion(ngx_event_t *ev)
{
    my_thread_ctx_t *ctx = ev->data;

    /* executed in nginx event loop */
}


ngx_int_t
my_task_offload(my_conf_t *conf)
{
    my_thread_ctx_t    *ctx;
    ngx_thread_task_t  *task;

    task = ngx_thread_task_alloc(conf->pool, sizeof(my_thread_ctx_t));
    if (task == NULL) {
        return NGX_ERROR;
    }

    ctx = task->ctx;

    ctx->foo = 42;

    task->handler = my_thread_func;
    task->event.handler = my_thread_completion;
    task->event.data = ctx;

    if (ngx_thread_task_post(conf->thread_pool, task) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
```

# 模块

## 添加新模块
每个独立的 nginx 模块驻留在一个单独的目录中，该目录至少包含两个文件：`config` 和一个模块源代码文件。`config` 文件包含 nginx 集成模块所需的所有信息，例如：
```shell
ngx_module_type=CORE
ngx_module_name=ngx_foo_module
ngx_module_srcs="$ngx_addon_dir/ngx_foo_module.c"

. auto/module

ngx_addon_name=$ngx_module_name
```
`config` 文件是一个 POSIX shell 脚本，可以设置和访问以下变量：

- ngx_module_type - 要构建的模块类型。可能的值为 CORE、HTTP、HTTP_FILTER、HTTP_INIT_FILTER、HTTP_AUX_FILTER、MAIL、STREAM 或 MISC。
- ngx_module_name - 模块名称。若要从一组源文件构建多个模块，请指定一个用空格分隔的名称列表。第一个名称指示动态模块的输出二进制文件的名称。列表中的名称必须与源代码中使用的名称匹配。
- ngx_addon_name - 配置脚本在控制台输出中显示的模块名称。
- ngx_module_srcs - 用于编译模块的源文件路径，以空格分隔。`$ngx_addon_dir` 变量可用于表示模块目录的路径。
- ngx_module_incs - 包含构建模块所需的路径。
- ngx_module_deps - 以空格分隔的模块依赖列表。通常，它是头文件的列表。
- ngx_module_libs - 要与模块链接的库列表，以空格分隔。例如，使用 `ngx_module_libs=-lpthread` 链接 `libpthread` 库。以下宏可以用于链接 nginx 相同的库：LIBXSLT、LIBGD、GEOIP、PCRE、OPENSSL、MD5、SHA1、ZLIB 和 PERL。
- ngx_module_link - 由构建系统设置为 `DYNAMIC`（动态模块）或 `ADDON`（静态模块）的变量，用于根据链接类型确定要执行的不同操作。
- ngx_module_order - 模块加载顺序；适用于 `HTTP_FILTER` 和 `HTTP_AUX_FILTER` 模块类型。此选项的格式是用空格分隔的模块列表。列表中跟随当前模块名称的所有模块都在模块全局列表中排在当前模块名称之后，该列表设置了模块初始化的顺序。对于过滤器模块，稍后初始化意味着更早的执行。以下模块通常用作参考。`ngx_http_copy_filter_module` 读取其他过滤器模块的数据，并位于列表底部附近，因此它是第一个要执行的。`ngx_http_write_filter_module` 将数据写入客户端套接字，并位于列表顶部附近，并且是最后一个被执行的。默认情况下，过滤器模块被放置在模块列表中的 `ngx_http_copy_filter` 之前，以便过滤器处理程序在拷贝过滤器处理程序之后执行。对于其他模块类型，默认值为空字符串。

要将模块静态编译成 nginx，请在 configure 脚本中使用 `--add-module=/path/to/module` 参数。要编译一个模块以便稍后动态加载到 nginx，请使用 `--add-dynamic-module=/path/to/module` 参数。

## 核心模块
模块是 nginx 的构建块，它的大部分功能都是作为模块实现的。模块源代码文件必须包含类型 `ngx_module_t` 的全局变量，定义如下：
```c
struct ngx_module_s {

    /* private part is omitted */

    void                 *ctx;
    ngx_command_t        *commands;
    ngx_uint_t            type;

    ngx_int_t           (*init_master)(ngx_log_t *log);

    ngx_int_t           (*init_module)(ngx_cycle_t *cycle);

    ngx_int_t           (*init_process)(ngx_cycle_t *cycle);
    ngx_int_t           (*init_thread)(ngx_cycle_t *cycle);
    void                (*exit_thread)(ngx_cycle_t *cycle);
    void                (*exit_process)(ngx_cycle_t *cycle);

    void                (*exit_master)(ngx_cycle_t *cycle);

    /* stubs for future extensions are omitted */
};
```
省略的私有部分包括模块版本和签名，并且使用预定义宏 `NGX_MODULE_V1` 填充。

每个模块将其私有数据保存在 `ctx` 字段中，识别在 `commands` 数组中指定的配置指令，并且可以在 nginx 生命周期的特定阶段调用。模块生命周期由以下事件组成：

- 配置指令处理程序在 master 进程上下文中的配置文件中出现时被调用。
- 配置解析成功后，在 master 进程的上下文中调用 `init_module` 处理程序。每次加载配置时，都会在 master 进程中调用 `init_module` 处理程序。
- master 进程创建一个或多个 worker 进程，并在每个 worker 进程中调用 `init_process` 处理程序。
- 当 worker 进程从 master 进程接收到 shutdown 或 terminate 命令时，它调用 `exit_process` 处理程序。
- master 进程在退出前调用 `exit_master` 处理程序。

由于线程在 nginx 中仅用作具有自己 API 的补充 I/O 工具，因此当前不调用 `init_thread` 和 `exit_thread` 处理程序。也没有 `init_master` 处理程序，因为这将是不必要的开销。

模块 `type` 确切定义了存储在 `ctx` 字段中的内容。其值为以下类型之一：

- NGX_CORE_MODULE
- NGX_EVENT_MODULE
- NGX_HTTP_MODULE
- NGX_MAIL_MODULE
- NGX_STREAM_MODULE

`NGX_CORE_MODULE` 是最基本的，因此也是最通用和最低级的模块类型。其他模块类型是在它之上实现的，并提供了一种更方便的方式来处理响应的请求，例如处理事件或 HTTP 请求。

核心模块集合包括 `ngx_core_module`、`ngx_errlog_module`、`ngx_regex_module`、`ngx_thread_pool_module` 和 `ngx_openssl_module` 模块。HTTP 模块、流模块、邮件模块和事件模块也是核心模块。核心模块的上下文定义为：
```c
typedef struct {
    ngx_str_t             name;
    void               *(*create_conf)(ngx_cycle_t *cycle);
    char               *(*init_conf)(ngx_cycle_t *cycle, void *conf);
} ngx_core_module_t;
```
其中 `name` 是模块名称字符串，`create_conf` 和 `init_conf` 分别是指向创建和初始化模块配置的函数的指针。对于核心模块，nginx 在解析配置之前调用 `create_conf`，在所有配置解析成功后调用 `init_conf`。典型的 `create_conf` 函数为配置分配内存并设置默认值。

例如，一个名为 `ngx_foo_module` 的简单模块可能如下所示：
```c
/*
 * Copyright (C) Author.
 */


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_flag_t  enable;
} ngx_foo_conf_t;


static void *ngx_foo_create_conf(ngx_cycle_t *cycle);
static char *ngx_foo_init_conf(ngx_cycle_t *cycle, void *conf);

static char *ngx_foo_enable(ngx_conf_t *cf, void *post, void *data);
static ngx_conf_post_t  ngx_foo_enable_post = { ngx_foo_enable };


static ngx_command_t  ngx_foo_commands[] = {

    { ngx_string("foo_enabled"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_foo_conf_t, enable),
      &ngx_foo_enable_post },

      ngx_null_command
};


static ngx_core_module_t  ngx_foo_module_ctx = {
    ngx_string("foo"),
    ngx_foo_create_conf,
    ngx_foo_init_conf
};


ngx_module_t  ngx_foo_module = {
    NGX_MODULE_V1,
    &ngx_foo_module_ctx,                   /* module context */
    ngx_foo_commands,                      /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_foo_create_conf(ngx_cycle_t *cycle)
{
    ngx_foo_conf_t  *fcf;

    fcf = ngx_pcalloc(cycle->pool, sizeof(ngx_foo_conf_t));
    if (fcf == NULL) {
        return NULL;
    }

    fcf->enable = NGX_CONF_UNSET;

    return fcf;
}


static char *
ngx_foo_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_foo_conf_t *fcf = conf;

    ngx_conf_init_value(fcf->enable, 0);

    return NGX_CONF_OK;
}


static char *
ngx_foo_enable(ngx_conf_t *cf, void *post, void *data)
{
    ngx_flag_t  *fp = data;

    if (*fp == 0) {
        return NGX_CONF_OK;
    }

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Foo Module is enabled");

    return NGX_CONF_OK;
}
```

## 配置指令
`ngx_command_t` 类型定义了单个配置指令。每个支持配置的模块都提供了这样的结构数组，这些结构描述了如何处理参数以及调用什么处理程序：
```c
typedef struct ngx_command_s  ngx_command_t;

struct ngx_command_s {
    ngx_str_t             name;
    ngx_uint_t            type;
    char               *(*set)(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
    ngx_uint_t            conf;
    ngx_uint_t            offset;
    void                 *post;
};
```
用特殊值 `ngx_null_command` 终止数组。`name` 是指令在配置文件中出现的名称，例如 "worker_processes" 或 "listen"。`type` 是一个标志位字段，它指定了该指令所接受的参数的数量，它的类型，以及它出现的上下文。标志有：

- NGX_CONF_NOARGS - 指令不接受参数。
- NGX_CONF_1MORE - 指令接受一个或多个参数。
- NGX_CONF_2MORE - 指令接受两个或多个参数。
- NGX_CONF_TAKE1..NGX_CONF_TAKE7 - 指令恰好采用指定数量的参数。
- NGX_CONF_TAKE12，NGX_CONF_TAKE13，NGX_CONF_TAKE23，NGX_CONF_TAKE123，NGX_CONF_TAKE1234 - 指令可以采用不同数量的参数。选项仅限于给定的数字。例如，NGX_CONF_TAKE12 意味着它需要一个或两个参数。

指令类型的标志包括：

- NGX_CONF_BLOCK - 指令是一个块，也就是说，它可以在它的左括号和右括号中包含其他指令，甚至可以实现自己的解析器来处理里面的内容。
- NGX_CONF_FLAG - 指令采用布尔值，`on` 或 `off`。

指令的上下文定义了它可能出现在配置中的位置：

- NGX_MAIN_CONF - 在顶层上下文中。
- NGX_HTTP_MAIN_CONF - 在 `http` 块中。
- NGX_HTTP_SRV_CONF - 在 `http` 块内的 `server` 块中。
- NGX_HTTP_LOC_CONF - 在 `http` 块内的 `location` 块中。
- NGX_HTTP_UPS_CONF - 在 `http` 块内的 `upstream` 块中。
- NGX_HTTP_SIF_CONF - 在 `http` 块内的 `server` 块内的 `if` 块中。
- NGX_HTTP_LIF_CONF - 在 `http` 块内的 `location` 块内的 `if` 块中。
- NGX_HTTP_LMT_CONF - 在 `http` 块内的 `limit_except` 块中。
- NGX_STREAM_MAIN_CONF - 在 `stream` 块中。
- NGX_STREAM_SRV_CONF - 在 `stream` 块内的 `server` 块中。
- NGX_STREAM_UPS_CONF - 在 `stream` 块内的 `upstream` 块中。
- NGX_MAIL_MAIN_CONF - 在 `mail` 块中。
- NGX_MAIL_SRV_CONF - 在 `mail` 块内的 `server` 块中。
- NGX_EVENT_CONF - 在 `event` 块中。
- NGX_DIRECT_CONF - 由不创建上下文层次结构并且只有一个全局配置的模块使用。此配置作为 `conf` 参数传递给处理程序。

配置解析器使用这些标志在指令放错位置的情况下抛出错误，并调用带有适当配置指针的指令处理程序，以便不同位置的相同指令可以将其值存储在不同的位置。

`set` 字段定义了一个处理程序，用于处理指令并将解析的值存储到响应的配置中。由许多函数可以执行常见的转换：

- ngx_conf_set_flag_slot - 将字面量字符串 `on` 和 `off` 转换为值分别为 1 和 0 的 `ngx_flag_t` 值。
- ngx_conf_set_str_slot - 将字符串存储为 `ngx_str_t` 类型的值。
- ngx_conf_set_str_array_slot - 将一个值追加到字符串 `ngx_str_t` 的数组 `ngx_array_t`。如果数组不存在，则创建该数组。
- ngx_conf_set_keyval_slot - 将键值对追加到键值对 `ngx_keyval_t` 的数组 `ngx_array_t`。第一个字符串成为键，第二个字符串成为值。如果数组不存在，则创建该数组。
- ngx_conf_set_num_slot - 将指令的参数转换为 `ngx_int_t` 值。
- ngx_conf_set_size_slot - 将[大小](https://nginx.org/en/docs/syntax.html)转换为以字节表示的 `size_t` 值。
- ngx_conf_set_off_slot - 将[偏移量](https://nginx.org/en/docs/syntax.html)转换为字节表示的 `off_t` 值。
- ngx_conf_set_msec_slot - 将[时间](https://nginx.org/en/docs/syntax.html)转换为以毫秒表示的 `ngx_msec_t` 值。
- ngx_conf_set_sec_slot - 将[时间](https://nginx.org/en/docs/syntax.html)转换为以秒表示的 `time_t` 值。
- ngx_conf_set_bufs_slot - 将提供的两个参数转换为一个 `ngx_bufs_t` 对象，该对象保存缓冲区的数量和[大小](https://nginx.org/en/docs/syntax.html)。
- ngx_conf_set_enum_slot - 将提供的参数转换为 `ngx_uint_t` 值。在 `post` 字段中传递的 `ngx_conf_enum_t` 以空结尾的数组定义了可接受的字符串和相应的整数值。
- ngx_conf_set_bitmask_slot - 将提供的参数转换为 `ngx_uint_t` 值。对每个参数的掩码进行 "或" 运算，以产生结果。在 `post` 字段中传递的 `ngx_conf_bitmask_t` 以空结尾的数组定义了可接受的字符串和相应的掩码值。
- set_path_slot - 将提供的参数转换为 `ngx_path_t` 值，并执行所有必须的初始化。有关详细信息，请参阅 [proxy_temp_path](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_temp_path) 指令的文档。
- set_access_slot - 将提供的参数转换为文件权限掩码。有关详细信息，请参阅 [proxy_store_access](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_store_access) 指令的文档。

`conf` 字段定义哪个配置结构被传递给目录处理程序。核心模块只有全局配置，并设置 `NGX_DIRECT_CONF` 标志访问它。HTTP、Stream 或 Mail 等模块创建了配置层次结构。例如，为 `server`、`location`、和 `if` 等作用域创建模块配置。

- NGX_HTTP_MAIN_CONF_OFFSET - `http` 块的配置。
- NGX_HTTP_SRV_CONF_OFFSET - `http` 块内 `server` 块的配置。
- NGX_HTTP_LOC_CONF_OFFSET - `http` 块内 `location` 块的配置。
- NGX_STREAM_MAIN_CONF_OFFSET - `stream` 块的配置。
- NGX_STREAM_SRV_CONF_OFFSET - `stream` 块内 `server` 块的配置。
- NGX_MAIL_CONF_OFFSET - `mail` 块的配置。
- NGX_MAIL_SRV_CONF_OFFSET - `mail` 块内 `server` 块的配置。

`offset` 定义了模块配置结构中的字段的偏移量，该结构保存了该特定指令的值。典型的用法是使用 `offsetof()` 宏。

`post` 字段有两个用途：它可以用于定义在主程序完成之后要调用的处理程序，或者将附加数据传递给主处理程序。在第一种情况下，需要使用指向句柄的指针初始化 `ngx_conf_post_t` 结构，例如：
```c
static char *ngx_do_foo(ngx_conf_t *cf, void *post, void *data);
static ngx_conf_post_t  ngx_foo_post = { ngx_do_foo };
```
`post` 参数是 `ngx_conf_post_t` 对象本身，`data` 是指向值的指针，该值由主程序以适当的类型转换而来。

# HTTP

## 连接
每个 HTTP 客户端连接都经过以下阶段：

- `ngx_event_accept()` 接受客户端 TCP 连接。调用此处理程序以响应监听套接字上的读通知。在此阶段创建一个新的 `ngx_connection_t` 对象，以包装新接受的客户端套接字。每个 nginx 监听器都提供了一个处理程序来传递新的连接对象。对于 HTTP 连接，它是 `ngx_http_init_connection(c)`。
- `ngx_http_init_connection()` 执行 HTTP 连接的早期初始化。在这个阶段，为连接创建一个 `ngx_http_connection_t` 对象，并将其引用存储在连接的 `data` 字段中。稍后它将被 HTTP 请求对象替换。代理协议解析器和 SSL 握手也在此阶段启动。
- `ngx_http_wait_request_handler()` 读事件处理程序当客户端套接字上有数据时被调用。在这个阶段，HTTP 请求对象 `ngx_http_request_t` 被创建并设置为连接的 `data` 字段。
- `ngx_http_process_request_line()` 读事件处理程序读取客户端请求行。处理程序由 `ngx_http_wait_request_handler()` 设置。数据被读入连接的 `buffer`。缓冲区的大小最初由 [client_header_buffer_size](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_header_buffer_size) 指令设置。整个客户端头应该适合缓冲区。如果初始大小不够，则分配更大的缓冲区，容量由 `large_client_header_buffers` 指令设置。
- `ngx_http_process_request_headers()` 读事件处理程序，设置在 `ngx_http_process_request_line()` 之后，用于读取客户端请求头。
- `ngx_http_core_run_phases()` 在请求头被完全读取和解析时被调用。此函数运行从 `NGX_HTTP_POST_READ_PHASE` 到 `NGX_HTTP_CONTENT_PHASE` 的请求阶段。最后一个阶段旨在生成响应并将其验证过滤器链传递。在此阶段不一定将响应发送到客户端。它可以保持缓冲状态，并在最终化阶段发送。
- `ngx_http_finalize_request()` 通常在请求生成所有输出或产生错误时被调用。在后一种情况下，查找适当的错误页并将其用作响应。如果此时响应没有完全发送到客户端，则 HTTP writer `ngx_http_writer()` 被激活以完成发送未完成的数据。
- 当完整的响应已经发送到客户端并且请求可以被销毁时调用 `ngx_http_finalize_connection()`。如果启用了客户端连接保持功能，则调用 `ngx_http_set_keepalive()`，该功能将销毁当前请求并等待连接上的下一个请求。否则，`ngx_http_close_request()` 将同时销毁请求和连接。

## 请求
对于每个客户端 HTTP 请求，创建 `ngx_http_request_t` 对象。此对象的一些字段包括：

- connection - 指向 `ngx_connection_t` 客户端连接对象的指针。多个请求可以同时引用同一个连接 - 一个主请求及其子请求。删除请求后，可以在同一连接上创建新请求。注意，对于 HTTP 连接，`ngx_connection_t` 的 `data` 字段指向请求。这种请求称为活动连接，而不是绑定到连接的其他请求。活动请求用于处理客户端连接事件，并允许将其响应输出到客户端。通常，每个请求在某个时刻变为活动状态，以便可以发送其输出。
- ctx - HTTP 模块上下文数组。类型 `NGX_HTTP_MODULE` 的每个模块可以在请求中存储任何值（通常是指向结构的指针）。该值存储在模块的 `ctx_index` 位置的 `ctx` 数组中。以下宏提供了获取和设置请求上下文的方便方法：
   - ngx_http_get_module_ctx(r, module) - 返回 `module` 的上下文
   - ngx_http_set_ctx(r, c, module) - 将 `c` 设置为 `module` 的上下文
- main_conf, srv_conf, loc_conf - 当前请求配置的数组。配置存储在模块的 `ctx_index` 位置。
- read_event_handler, write_event_handler - 读取和写入请求的事件处理程序。通常，HTTP 连接的读写事件处理程序都设置为 `ngx_http_request_handler()`。此函数调用当前活动请求的 `read_event_handler` 和 `write_event_handler` 处理程序。
- cache - 用于缓存上游响应的请求缓存对象。
- upstream - 请求上游对象进行代理。
- pool - 请求池。请求对象本身在此池中分配，当请求被删除时，此池将被销毁。对于需要在客户端连接的整个生命周期中可用的分配，请改用 `ngx_connection_t` 的池。
- header_in - 客户端 HTTP 请求报头被读取到的缓冲区。
- headers_in, headers_out - 输入和输出 HTTP 头对象。这两个对象都包含 `ngx_list_t` 类型的 `headers` 字段，用于保存原始的头列表。初次之外，特定的标题可用于获取和设置为单独的字段，例如 `content_length_n`、`status` 等。
- request_body - 客户端请求主体对象。
- start_sec, start_msec - 请求创建的时间点，用于跟踪请求持续时间。
- method, method_name - 客户端 HTTP 请求方法的数字和文本表示。方法的数值在 `src/http/ngx_http_request.h` 中定义，宏 `NGX_HTTP_GET`、`NGX_HTTP_HEAD`、`NGX_HTTP_POST` 等。
- http_protocol - 客户端 HTTP 协议的原始文本形式（"HTTP/1.0"、"HTTP/1.1" 等）。
- http_version - 客户端 HTTP 协议的数字形式（`NGX_HTTP_VERSION_10`、`NGX_HTTP_VERSION_11` 等）。
- http_major，http_minor - 客户端 HTTP 协议版本，以数字形式分为主要部分和次要部分。
- request_line, unparsed_uri - 原始客户端请求中的请求行和 URI。
- uri，args，exten - 当前请求的 URI、参数和文件扩展名。由于规范化，这里的 URI 值可能与客户端发送的原始 URI 不同。在整个请求处理过程中，这些值可以随着执行内部重定向而改变。
- main - 指向主请求对象的指针。创建此对象是为了处理客户端 HTTP 请求，而不是子请求，后者是为了执行主请求中的特定子任务而创建的。
- parent - 指向子请求的父请求的指针。
- postponed - 输出缓冲区和子请求的列表，按照发送和创建它们的顺序。当列表的一部分由子请求创建时，延迟过滤器使用该列表提供一致的请求输出。
- post_subrequest - 指向处理程序的指针，当子请求完成时，该处理程序具有要调用的上下文。未用于主请求。
- posted_requests - 要启动或恢复的请求列表，这是通过调用请求的 `write_event_handler` 来完成的。通常，这个处理程序保存请求主函数，该函数首先运行请求阶段，然后生成输出。请求通常由 `ngx_http_post_request(r, NULL)` 调用发布。它总是发布到主请求 `posted_requests`列表中。函数 `ngx_http_run_posted_requests(c)` 运行在所传递连接的活动请求的主请求中发布的所有请求。所有事件处理程序都调用 `ngx_http_run_posted_requests`，这可能导致新的提交请求。通常，它是在调用请求的读或写处理程序之后调用的。
- phase_handler - 当前请求阶段的索引。
- ncaptures, captures, captures_data - 由请求的最后一个正则表达式匹配生成的正则表达式捕获。在请求处理过程中，正则表达式匹配可能发生在多个位置：映射查找、SNI 或 HTTP 主机的服务器查找、重写、代理重定向等。由查找产生的捕获存储在上述字段中。字段 `ncaptures` 保存捕获次数，`captures` 保存捕获边界，`captures_data` 保存正则表达式匹配的字符串，该字符串用于提取捕获。在每次正则表达式匹配之后，请求捕获被重置以保存新的值。
- count - 请求引用计数器。该字段仅对主请求有意义。通过简单的 `r->main->count++` 来增加技术。要减少计数器，请调用 `ngx_http_finalize_request(r, rc)`。创建子请求和运行请求主体读处理都会增加计数器。
- subrequests - 当前子请求嵌套级别。每个子请求都继承其父请求的嵌套级别，并减一。如果值达到零，则生成错误。主请求的值由 `NGX_HTTP_MAX_SUBREQUESTS` 常量定义。
- uri_changes - 请求剩余的 URI 更改数。一个请求可以更改其 URI 的总次数受到 `NGX_HTTP_MAX_URI_CHANGES` 常量的限制。每次改变，值递减，直到它达到零，此时产生错误。重写和内部重定向到正常位置或命名位置被视为 URI 更改。
- blocked - 请求上持有的块计数器。当此值为非零时，无法终止请求。目前，这个值是通过挂起的 AIO 操作（POSIX AIO 和线程操作）和活动缓冲锁定而增加的。
- buffered - 显示哪些模块缓冲了请求产生的输出的位掩码。多个滤波器可以缓冲输出；例如，sub_filter 可以因为部分字符串匹配而缓冲数据，copy filter 可以因为缺少空闲输出缓冲区而缓冲数据，等等。只要该值不为零，请求就不会在等待刷新时完成。
- header_only - 表示输出不需要包体的标志。例如，HTTP HEAD 请求使用此标志。
- keepalive - 指示是否支持客户端连接保活的标志。该值是从 HTTP 版本和 "Connection" 头的值推断出来的。
- header_sent - 指示输出报头已经由请求发送的标志。
- internal - 指示当前请求是内部请求的标志。要进入内部状态，请求必须通过内部重定向或者是子请求。允许内部请求进入内部位置。
- allow_ranges - 指示可以根据 HTTP Range 报头的请求将部分响应发送到客户端的标志。
- subrequest_ranges - 指示在处理子请求时可以发送部分响应的标志。
- single_range - 指示只能向客户端发送单个连续范围的输出数据的标志。此标准通常在发送数据流时设置，例如从代理服务器发送，并且整个响应在一个缓冲区中不可用。
- main_filter_need_in_memory, filter_need_in_memory - 请求输出在内存缓冲区而不是文件中产生的标志。这是一个信号，即使 sendfile 被启用，copy filter 也会从文件缓冲区读取数据。这两个标志之间的区别在于设置它们的过滤器模块的位置。在过滤器链集合 `filter_need_in_memory` 中的推迟过滤器之前调用的过滤器，请求仅当前请求输出进入内存缓冲区。在过滤器链集合 `main_filter_need_in_memory` 中稍后调用的过滤器，请求主请求和所有子请求在发送输出时读取内存中的文件。
- filter_need_temporary - 请求在临时缓冲区中而不是在只读内存缓冲区或文件缓冲区中产生请求输出的标志。这是由过滤器使用的，过滤器可以直接在发送输出的缓冲区中更改输出。

## 配置
每个 HTTP 模块可以有三种类型的配置：

- 主配置 - 适用于整个 `http` 块。用作模块的全局设置。
- 服务器配置 - 应用于单个 `server` 块。用作模块的特定于服务器的设置。
- 位置配置 - 适用于单个 `location`、`if` 或 `limit_except` 块。用作模块的特定位置设置。

配置结构是在 nginx 配置阶段通过调用函数创建的，函数分配给结构，初始化它们并合并它们。下面是示例演示如何为模块创建简单的位置配置。配置有一个无符号整数类型的设置 `foo`。
```c
typedef struct {
    ngx_uint_t  foo;
} ngx_http_foo_loc_conf_t;


static ngx_http_module_t  ngx_http_foo_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_foo_create_loc_conf,          /* create location configuration */
    ngx_http_foo_merge_loc_conf            /* merge location configuration */
};


static void *
ngx_http_foo_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_foo_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_foo_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->foo = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_foo_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_foo_loc_conf_t *prev = parent;
    ngx_http_foo_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->foo, prev->foo, 1);
}
```
如示例所示，`ngx_http_foo_create_loc_conf()` 函数创建了一个新的配置结构，`ngx_http_foo_merge_loc_conf()` 将配置与更高级别的配置合并。事实上，server 配置和 location 配置不仅存在于 server 和 location 级别，而且还为它们之上的所有级别创建。具体地，还在 main 级别创建 server 配置，并且在 main 级别、server 级别和 location 级别创建 location 配置。这些配置使得可以在 nginx 配置文件的任何级别指定特定于服务器和位置的设置。最终配置被合并下来。提供了许多宏，如 `NGX_CONF_UNSET` 和 `NGX_CONF_UNSET_UINT`，用于指示丢失的设置并在合并时忽略它。标准的 nginx 合并宏（如 `ngx_conf_merge_value()` 和 `ngx_conf_merge_uint_value()`）提供了一种方便的方式来合并设置，并在没有配置提供显示值的情况下设置默认值。有关不同类型宏的完整列表，请参见 `src/core/ngx_conf_file.h`。

以下宏可用于在配置时访问 HTTP 模块的配置。它们都以 `ngx_conf_t` 引用作为第一个参数。

- ngx_http_conf_get_module_main_conf(cf, module)
- ngx_http_conf_get_module_srv_conf(cf, module)
- ngx_http_conf_get_module_loc_conf(cf, module)

下面的示例获取一个指向标准 nginx 核心模块 [ngx_http_core_module](https://nginx.org/en/docs/http/ngx_http_core_module.html) 的 location 配置的指针，并替换结构 `handler` 字段中保存的 locaiton 内容处理程序。
```c
static ngx_int_t ngx_http_foo_handler(ngx_http_request_t *r);


static ngx_command_t  ngx_http_foo_commands[] = {

    { ngx_string("foo"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_foo,
      0,
      0,
      NULL },

      ngx_null_command
};


static char *
ngx_http_foo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_bar_handler;

    return NGX_CONF_OK;
}
```
以下宏可用于在运行时访问 HTTP 模块的配置。

- ngx_http_get_module_main_conf(r, module)
- ngx_http_get_module_srv_conf(r, module)
- ngx_http_get_module_loc_conf(r, module)

这些宏接受 HTTP 请求 `ngx_http_request_t` 的引用。请求的主配置永远不会更改。在为请求选择虚拟服务器后，server 配置可以从默认值更改。由于重写操作或内部重定向，为处理请求而选择的 location 配置可能会更改多次。下面的示例演示如何在运行时访问模块的 HTTP 配置。
```c
static ngx_int_t
ngx_http_foo_handler(ngx_http_request_t *r)
{
    ngx_http_foo_loc_conf_t  *flcf;

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_foo_module);

    ...
}
```

## 阶段
每个 HTTP 请求都经过一系列的阶段。在每个阶段中，对请求执行不同类型的处理。模块特定的处理程序可以在大多数阶段中注册，许多标准的 nginx 模块注册阶段处理程序，作为在请求处理的特定阶段被调用的一种方式。阶段被连续处理，并且一旦请求到达阶段，阶段处理程序被调用。以下是 nginx HTTP 阶段的列表。

- **NGX_HTTP_POST_READ_PHASE** - 第一阶段。[ngx_http_realip_module](https://nginx.org/en/docs/http/ngx_http_realip_module.html) 在此阶段注册其处理程序，以便在调用任何其他模块之前启用客户端地址的替换。
- **NGX_HTTP_SERVER_REWRITE_PHASE** - 处理在 `server` 块中（但在 `location` 块之外）定义的重写指令的阶段。[ngx_http_rewrite_module](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html) 在此阶段安装其处理程序。
- **NGX_HTTP_FIND_CONFIG_PHASE** - 根据请求 URI 选择位置的特殊阶段。在此阶段之前，相关虚拟服务器的默认 location 被分配给请求，并且请求 location 配置的任何模块接受默认 server 位置的配置。此阶段为请求分配新 location。此阶段无法注册其他处理程序。
- **NGX_HTTP_REWRITE_PHASE** - 与 `NGX_HTTP_SERVER_REWRITE_PHASE` 相同，但适用于在前一阶段选择的 location 中定义的重写规则。
- **NGX_HTTP_POST_REWRITE_PHASE** - 特殊阶段，如果在重写过程中请求的 URI 发生了变化，则请求将被重定向到一个新的位置。这是通过请求再次通过 `NGX_HTTP_FIND_CONFIG_PHASE` 来实现的。此阶段无法注册其他处理程序。
- **NGX_HTTP_PREACCESS_PHASE** - 不同类型的处理程序的公共阶段，与访问控制无关。标准 nginx 模块 [ngx_http_limit_conn_module](https://nginx.org/en/docs/http/ngx_http_limit_conn_module.html) 和 [ngx_http_limit_req_module](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html) 在此阶段注册了它们的处理程序。
- **NGX_HTTP_ACCESS_PHASE** - 验证客户端是否被授权发出请求的阶段。标准的 nginx 模块，如果 [ngx_http_access_module](https://nginx.org/en/docs/http/ngx_http_access_module.html) 和 [ngx_http_auth_basic_module](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html) 在此阶段注册了它们的处理程序。默认情况下，客户端必须通过在此阶段注册的所有处理程序的授权检查，以便请求继续到下一阶段。如果阶段处理程序中的任何一个授权了客户端，则[满足](https://nginx.org/en/docs/http/ngx_http_core_module.html#satisfy)指令可用于允许处理继续。
- **NGX_HTTP_POST_ACCESS_PHASE** - 处理[满足任何](https://nginx.org/en/docs/http/ngx_http_core_module.html#satisfy)指令的特殊阶段。如果某些访问阶段处理程序拒绝了访问，并且没有一个处理程序显式地允许访问，则请求被终结。此阶段无法注册其他处理程序。
- **NGX_HTTP_PRECONTENT_PHASE** - 生成内容之前要调用的处理程序阶段。[ngx_http_try_files_module](https://nginx.org/en/docs/http/ngx_http_core_module.html#try_files) 和 [ngx_http_mirror_module](https://nginx.org/en/docs/http/ngx_http_mirror_module.html) 等标准模块在此阶段注册它们的处理程序。
- **NGX_HTTP_CONTENT_PHASE** - 正常生成响应的阶段。多个 nginx 标准模块在此阶段注册了它们的处理程序，包括 [ngx_http_index_module](https://nginx.org/en/docs/http/ngx_http_index_module.html) 或 `ngx_http_static_module`。它们被顺序调用，直到其中一个产生输出。也可以在每个位置的基础上设置内容处理程序。如果 [ngx_http_core_module](https://nginx.org/en/docs/http/ngx_http_core_module.html) 的 location 配置设置了 `handler`，它将作为内容处理程序调用，并且忽略在此阶段安装的处理程序。
- **NGX_HTTP_LOG_PHASE** - 执行请求日志记录的阶段。目前，只有 [ngx_http_log_module](https://nginx.org/en/docs/http/ngx_http_log_module.html) 在此阶段注册其处理程序以进行访问日志记录。日志阶段处理程序是在请求处理的最后，也就是释放请求之前调用的。

以下是预访问阶段处理程序的示例。
```c
static ngx_http_module_t  ngx_http_foo_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_foo_init,                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


static ngx_int_t
ngx_http_foo_handler(ngx_http_request_t *r)
{
    ngx_table_elt_t  *ua;

    ua = r->headers_in.user_agent;

    if (ua == NULL) {
        return NGX_DECLINED;
    }

    /* reject requests with "User-Agent: foo" */
    if (ua->value.len == 3 && ngx_strncmp(ua->value.data, "foo", 3) == 0) {
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_foo_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_foo_handler;

    return NGX_OK;
}
```
阶段处理程序应该返回特定的代码：

- **NGX_OK** - 进入下一阶段。
- **NGX_DECLINED** - 进入当前阶段的下一个处理程序。如果当前处理程序是当前阶段中的最后一个，则转到下一个阶段。
- **NGX_AGAIN, NGX_DONE** - 暂停阶段处理，直到将某个将来的事件，例如，可能是异步 I/O 操作或只是延迟。假设稍后通过调用 `ngx_http_core_run_phases()` 来恢复阶段处理。
- 极端处理程序返回的任何其他值都被视为请求终止代码，特别是 HTTP 响应代码。使用提供的代码完成请求。

对于某些阶段，返回代码的处理方式略有不同。在内容阶段，除 `NGX_DECLINED` 之外的任何返回代码都被认为是终止代码。来自 location 内容处理程序的任何返回代码都被视为终结代码。在访问阶段，在满足任何模式时，除 `NGX_OK`、`NGX_DECLINED`、`NGX_AGAIN`、`NGX_DONE` 之外的任何返回码被认为是拒绝。如果没有后续访问处理程序允许或拒绝使用其他代码进行访问，则拒绝代码将成为终结代码。

# 变量

## 访问现有变量
变量可以通过索引（这是最常见的方法）或名称（见下文）引用。当变量被添加到配置时，在配置阶段创建索引。要获得变量索引，请使用 `ngx_http_get_variable_index()`：
```c
ngx_str_t  name;  /* ngx_string("foo") */
ngx_int_t  index;

index = ngx_http_get_variable_index(cf, &name);
```
这里，`cf` 是指向 nginx 配置的指针，`name` 指向包含变量名的字符串。该函数在出现错误时返回 `NGX_ERROR`，否则返回有效索引，该索引通常存储在模块配置中的某个位置以供将来使用。

所有 HTTP 变量都在给定 HTTP 请求的上下文中进行评估，结果特定于该 HTTP 请求并缓存在该 HTTP 请求中。所有计算变量的函数返回 `ngx_http_variable_value_t` 类型，表示变量值：
```c
typedef ngx_variable_value_t  ngx_http_variable_value_t;

typedef struct {
    unsigned    len:28;

    unsigned    valid:1;
    unsigned    no_cacheable:1;
    unsigned    not_found:1;
    unsigned    escape:1;

    u_char     *data;
} ngx_variable_value_t;
```
其中：

- len - 值的长度
- data - 值本身
- valid - 值有效
- not_found - 未找到变量，因此 `data` 和 `len` 字段不相关；例如，当请求中没有传递相应的参数时，类似 `$arg_foo` 的变量可能会发生这种情况
- no_cacheable - 不缓存结果
- escape - 由日志模块内部使用，用于标记输出时需要转义的值

`ngx_http_get_flushed_variable()` 和 `ngx_http_get_indexed_variable()` 函数用于获取变量的值。它们具有相同的接口 - 接受 HTTP 请求 `r` 作为评估变量的上下文，以及标识变量的 `index`。典型用法示例：
```c
ngx_http_variable_value_t  *v;

v = ngx_http_get_flushed_variable(r, index);

if (v == NULL || v->not_found) {
    /* we failed to get value or there is no such variable, handle it */
    return NGX_ERROR;
}

/* some meaningful value is found */
```
它们之间的区别在于，`ngx_http_get_indexed_variable()` 返回缓存值，`ngx_http_get_flushed_variable()` 刷新该高速缓存中不可缓存的变量。

有些模块，如 SSI 和 Perl，需要处理在配置时名称未知的变量。因此，索引不能用于访问它们，但 `ngx_http_get_variable(r, name, key)` 函数可用。它搜索一个具有给定 `name` 的变量，其哈希 `key` 从该名称派生。

## 创建变量
要创建变量，请使用 `ngx_http_add_variable()` 函数。它接受配置（变量注册的位置），变量名和控制函数行为的标志作为参数：

- **NGX_HTTP_VAR_CHANGEABLE** - 启用变量的重定义：如果另一个模块定义具有相同名称的变量，则不存在冲突。这允许 [set](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#set) 指令覆盖变量。
- **NGX_HTTP_VAR_NOHASH** - 表示此变量只能通过索引访问，不能通过名称访问。当已知 SSI 或 Perl 等模块中不需要变量时，这是一个小的优化。
- **NGX_HTTP_VAR_PREFIX** - 变量名是前缀。在这种情况下，处理程序必须实现额外的逻辑来获取特定变量的值。例如，所有 "arg_" 变量都由同一个处理程序处理，该处理程序在请求参数中执行查找并返回特定参数的值。

如果出现错误，函数返回 NULL，否则返回指向 `ngx_http_variable_t` 的指针：
```c
struct ngx_http_variable_s {
    ngx_str_t                     name;
    ngx_http_set_variable_pt      set_handler;
    ngx_http_get_variable_pt      get_handler;
    uintptr_t                     data;
    ngx_uint_t                    flags;
    ngx_uint_t                    index;
};
```
`get` 和 `set` 处理程序被调用以获取或设置变量值，`data` 被传递给变量处理程序，`index` 保存用于引用变量的指定变量索引。

通常，一个以空终止的 `ngx_http_variable_t` 结构的静态数组由模块创建，并在预配置阶段进行处理，以将变量添加到配置中，例如：
```c
static ngx_http_variable_t  ngx_http_foo_vars[] = {

    { ngx_string("foo_v1"), NULL, ngx_http_foo_v1_variable, 0, 0, 0 },

      ngx_http_null_variable
};

static ngx_int_t
ngx_http_foo_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_foo_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}
```
示例中的这个函数用于初始化 HTTP 模块上下文的 `preconfiguration` 字段，在解析 HTTP 配置之前调用，以便解析器可以引用这些变量。

`get` 处理程序负责在特定请求的上下文中计算变量，例如：
```c
static ngx_int_t
ngx_http_variable_connection(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = ngx_pnalloc(r->pool, NGX_ATOMIC_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%uA", r->connection->number) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}
```
如果出现内部错误（例如内存分配失败），则返回 `NGX_ERROR`，否则返回 `NGX_OK`。要了解变量求值的状态，请检查 `ngx_http_variable_value_t` 中的标志（参见上面的描述）。

`set` 处理程序允许设置变量引用的属性。例如，`$limit_rate` 变量的 set 处理程序修改请求的 `limit_rate` 字段：
```c
...
{ ngx_string("limit_rate"), ngx_http_variable_request_set_size,
  ngx_http_variable_request_get_size,
  offsetof(ngx_http_request_t, limit_rate),
  NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 0 },
...

static void
ngx_http_variable_request_set_size(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ssize_t    s, *sp;
    ngx_str_t  val;

    val.len = v->len;
    val.data = v->data;

    s = ngx_parse_size(&val);

    if (s == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid size \"%V\"", &val);
        return;
    }

    sp = (ssize_t *) ((char *) r + data);

    *sp = s;

    return;
}
```

## 复杂值
尽管其名为复杂值，但提供了一种简单的方法来计算表达式，表达式可以包含文本、变量及其组合。

`ngx_http_complie_complex_value` 中的复杂值描述在配置阶段被编译成 `ngx_http_complex_value_t`，在运行时使用，以获得表达式求值的结果。
```c
ngx_str_t                         *value;
ngx_http_complex_value_t           cv;
ngx_http_compile_complex_value_t   ccv;

value = cf->args->elts; /* directive arguments */

ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

ccv.cf = cf;
ccv.value = &value[1];
ccv.complex_value = &cv;
ccv.zero = 1;
ccv.conf_prefix = 1;

if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
    return NGX_CONF_ERROR;
}
```
这里，`ccv` 保存初始化复杂值 `cv` 所需的所有参数：

- cf - 配置指针
- value - 待解析字符串（输入）
- complex_value - 编译值（输出）
- zero - 启用零终止值的标志
- conf_prefix - 在结果中添加配置前缀（nginx 当前查找配置的目录）
- root_prefix - 在结果中添加 root 前缀（普通 nginx 安装前缀）

当结果要传递给需要以零结尾字符串的库时，`zero` 标志很有用，而前缀在处理文件名时也很方便。

编译成功后，`cv.lengths` 包含有关表达式中变量存在的信息。 NULL 值意味着表达式仅包含静态文本，因此可以存储在简单字符串中，而不是作为复杂值存储。

`ngx_http_set_complex_value_slot()` 是一个方便的函数，用于在指令声明本身中完全初始化复杂值。

在运行时，可以用 `ngx_http_complex_value()` 函数计算复数值：
```c
ngx_str_t  res;

if (ngx_http_complex_value(r, &cv, &res) != NGX_OK) {
    return NGX_ERROR;
}
```
给定请求 `r` 和先前编译的值 `cv`，函数计算表达式结果并将结果写入 `res`。

## 请求重定向
HTTP 请求总是通过 `ngx_http_request_t` 结构的 `loc_conf` 字段连接到一个位置。这意味着在任何一点上，任何模块的配置都可以通过调用 `ngx_http_get_module_loc_conf(r, module)` 从请求中检索。在请求的生存期内，请求位置可能会更改数次。最初，默认服务器的默认服务器位置被分配给请求。如果请求切换到不同的服务器（由 HTTP "Host" 或 SSL SNI 扩展选择），则请求也切换到该服务器的默认位置。位置的下一次改变发生在 `NGX_HTTP_FIND_CONFIG_PHASE` 请求阶段。在此阶段，请求 URI 在为服务器配置的所有未命名位置中选择一个位置。[ngx_http_rewrite_module](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html) 可以在 `NGX_HTTP_REWRITE_PHASE` 请求阶段改变请求 URI 作为 [rewrite](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#rewrite) 指令的结果，并且将请求发送回 `NGX_HTTP_FIND_CONFIG_PHASE` 阶段以用于基于新 URI 选择新位置。

也可以通过调用 `ngx_http_internal_redirect(r, ui, args)` 或 `ngx_http_named_location(r, name)` 中的一个将请求重定向到任何新的位置。

`ngx_http_internal_redirect(r, uri, args)` 函数更改请求 URI 并将请求返回到 `NGX_HTTP_SERVER_REWRITE_PHASE` 阶段。请求将继续使用服务器默认位置。稍后在 `NGX_HTTP_FIND_CONFIG_PHASE` 处，基于新的请求 URI 选择新的位置。

下面的示例使用新的请求参数执行内部重定向。
```c
ngx_int_t
ngx_http_foo_redirect(ngx_http_request_t *r)
{
    ngx_str_t  uri, args;

    ngx_str_set(&uri, "/foo");
    ngx_str_set(&args, "bar=1");

    return ngx_http_internal_redirect(r, &uri, &args);
}
```
函数 `ngx_http_named_location(r, name)` 将请求重定向到指定位置。位置的名称作为参数传递。在当前服务器的所有命名位置中找到该位置，之后请求切换到 `NGX_HTTP_REWRITE_PHASE` 阶段。

下面的示例执行重定向到命名的 location @foo。
```c
ngx_int_t
ngx_http_foo_named_redirect(ngx_http_request_t *r)
{
    ngx_str_t  name;

    ngx_str_set(&name, "foo");

    return ngx_http_named_location(r, &name);
}
```
在 nginx 模块已经在请求的 `ctx` 字段中存储了一些上下文时，可以调用函数 `ngx_http_internal_redirect(r, uri, args)` 和 `ngx_http_named_location(r, name)`。这些上下文可能与新的 location 配置不一致。为了防止不一致，所有请求上下文都被两个重定向函数擦除。

调用 `ngx_http_internal_redirect(r, uri, args)` 或 `ngx_http_named_location(r, name)` 会增加请求 `count`。为了获得一致的请求引用计数，请在重定向请求后调用 `ngx_http_finalize_requests(r, NGX_DONE)`。这将完成当前请求代码路径并减少计数器。

重定向和重写的请求变为内部请求，可以访问[内部](https://nginx.org/en/docs/http/ngx_http_core_module.html#internal)位置。内部请求设置了 `internal` 标志。

## 子请求
子请求主要用于将一个请求的输出插入到另一个请求中，可能与其他数据混合在一起。子请求看起来像一个普通请求，但与其父请求共享一些数据。特别地，与客户端输入相关的所有字段都被共享，因为子请求不接收来自客户端的任何其他输入。子请求的请求字段 `parent` 包含到其父请求的链接，主请求为 NULL。字段 `main` 包含到请求组中的主请求的链接。

子请求在 `NGX_HTTP_SERVER_REWRITE_PHASE` 阶段开始。它经过与普通请求相同的后续阶段，并根据其自身的 URI 分配位置。

子请求中的输出标头总是被忽略。`ngx_http_postpone_filter` 将子请求的输出主体放置在相对于父请求生成的其他数据的正确位置。

子请求与活动请求的概念有关。如果请求 `c->data == r`，则请求 `r` 被认为是活动的，其中 `c` 是客户端的连接对象。在任何给定点，只有请求组中的活动请求被允许将其缓冲区输出到客户端。一个非活动的请求仍然可以将其输出发送到过滤器链，但它不会超过 `ngx_http_postpone_filter`，并保持由该过滤器缓冲，直到请求变为活动。以下是一些请求激活的规则：

- 最初，主请求是活动。
- 活动请求的第一个子请求在创建后立即变为活动。
- `ngx_http_postpone_filter` 激活活动请求的子请求列表中的下一个请求，一旦该请求之前的所有数据被发送。
- 当一个请求完成后，它的父请求被激活。

调用函数 `ngx_http_subrequest(r, uri, args, psr, ps, flags)` 创建子请求，其中 `r` 是父请求，`uri` 和 `args` 是子请求的 URI 和参数，`psr` 是输出参数，它接收新创建的子请求引用，`ps` 是回调对象，用于通知父请求子请求正在完成，`flags` 是标志的位掩码。以下标志可用：

- NGX_HTTP_SUBREQUEST_IN_MEMORY - 输出不发送到客户端，而是存储在内存中。该标志只影响由代理模块之一处理的子请求。子请求完成后，其输出在类型 `ngx_buf_t` 的 `r->out` 中可用。
- NGX_HTTP_SUBREQUEST_WAITED - 子请求的 `done` 标志被设置，即使子请求在其最终确定时不活动。此子请求的标志由 SSI 过滤器使用。
- NGX_HTTP_SUBREQUEST_CLONE - 子请求被创建为其父请求的克隆。它在父请求相同的位置启动并从相同的阶段继续。

下面的示例创建了一个 URI 为 `/foo` 的子请求。
```c
ngx_int_t            rc;
ngx_str_t            uri;
ngx_http_request_t  *sr;

...

ngx_str_set(&uri, "/foo");

rc = ngx_http_subrequest(r, &uri, NULL, &sr, NULL, 0);
if (rc == NGX_ERROR) {
    /* error */
}
```

此示例克隆当前请求并为子请求设置终止回调。
```c
ngx_int_t
ngx_http_foo_clone(ngx_http_request_t *r)
{
    ngx_http_request_t          *sr;
    ngx_http_post_subrequest_t  *ps;

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_ERROR;
    }

    ps->handler = ngx_http_foo_subrequest_done;
    ps->data = "foo";

    return ngx_http_subrequest(r, &r->uri, &r->args, &sr, ps,
                               NGX_HTTP_SUBREQUEST_CLONE);
}


ngx_int_t
ngx_http_foo_subrequest_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    char  *msg = (char *) data;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "done subrequest r:%p msg:%s rc:%i", r, msg, rc);

    return rc;
}
```

子请求通常在主体过滤器中创建，在这种情况下，它们的输出可以像任何显示请求的输出一样被处理。这意味着子请求的输出最终会在子请求创建之前传递的所有显式缓冲区之后以及创建之后传递的任何缓冲区之前发送到客户端。即使对于子请求的大层次结构也会保留这种顺序。下面的示例在所有请求数据缓冲区之后插入子请求的输出，但在带有 `last_buf` 标志的最后一个缓冲区之前。
```c
ngx_int_t
ngx_http_foo_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                   rc;
    ngx_buf_t                  *b;
    ngx_uint_t                  last;
    ngx_chain_t                *cl, out;
    ngx_http_request_t         *sr;
    ngx_http_foo_filter_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_foo_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    last = 0;

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            cl->buf->last_buf = 0;
            cl->buf->last_in_chain = 1;
            cl->buf->sync = 1;
            last = 1;
        }
    }

    /* Output explicit output buffers */

    rc = ngx_http_next_body_filter(r, in);

    if (rc == NGX_ERROR || !last) {
        return rc;
    }

    /*
     * Create the subrequest.  The output of the subrequest
     * will automatically be sent after all preceding buffers,
     * but before the last_buf buffer passed later in this function.
     */

    if (ngx_http_subrequest(r, ctx->uri, NULL, &sr, NULL, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, NULL, ngx_http_foo_filter_module);

    /* Output the final buffer with the last_buf flag */

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last_buf = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}
```
子请求也可以被创建用于数据输出以外的目的。例如，ngx_http_auth_request_module 模块在 `NGX_HTTP_ACCESS_PHASE` 阶段创建子请求。要在此时禁止输出，在子请求上设置 `header_only` 标志。这防止子请求体被发送到客户端。注意子请求的头永远不会发送到客户端。可以在回调处理程序中分析子请求的结果。

## 请求完成
HTTP 请求通过调用函数 `ngx_http_finalize_request(r, rc)` 来完成。它通常在所有输出缓冲区发送到过滤器链之后由内容处理程序完成。此时，所有的输出可能不会发送到客户端，其中的一些仍然被缓存在过滤器链沿着某个地方。如果是，`ngx_http_finalize_request(r, rc)` 函数会自动安装一个特殊的处理程序 `ngx_http_writer(r)` 来完成输出的发送。如果出现错误或需要向客户端返回标准 HTTP 响应代码，请求也会最终确定。

函数 `ngx_http_finalize_request(r, rc)` 需要以下 `rc` 值：

- NGX_DONE - 快速完成。减少请求 `count`，如果请求达到零则销毁请求。在当前请求被销毁后，客户端连接可以用于更多请求。
- NGX_ERROR, NGX_HTTP_REQUEST_TIME_OUT(408), NGX_HTTP_CLIENT——CLOSE_REQUEST(499) - 错误借宿。尽快终止请求并关闭客户端连接。
- NGX_HTTP_CREATED(201)，NGX_HTTP_NO_CONTENT(204)，大于或等于 NGX_HTTP_SPECIAL_RESPONSE(300) 的代码 - 特殊响应结束。对于这些值，nginx 要么向客户端发送代码的默认响应页面，要么执行内部重定向到 error_page 位置（如果为代码配置了该位置）。
- 其他代码被认为是成功的完成代码，并且可能激活请求写入器以完成发送响应正文。一旦主体被完全发送，请求 `count` 被递减。如果它达到零，则请求被销毁，但客户端连接仍然可以用与其他请求。如果 `count` 是肯定的，则请求中有未完成的活动，将在稍后的时间完成。

## 请求体
为了处理客户端请求的主体，nginx 提供了 `ngx_http_read_client_request_body(r, post_handler)` 和 `ngx_http_discard_request_body(r)` 函数。第一个函数读取请求主体并通过 `request_body` 请求字段使其可用。第二个函数指示 nginx 丢弃（读取并忽略）请求体。每个请求都必须调用这些函数之一。通常由内容处理程序进行调用。

不允许从子请求中读取或丢弃客户端请求正文。它必须始终在主请求中完成。当创建子请求时，它继承父请求的 `request_body` 对象，如果主请求先前读取了请求体，则子请求可以使用该对象。

函数 `ngx_http_read_client_request_body(r, post_handler)` 开始读取请求主体的处理。当主体被完全读取时，调用 `post_handler` 回调函数继续处理请求。如果请求正文丢失或已被读取，则立即调用回调。函数 `ngx_http_read_client_request_body(r, post_handler)` 分配类型 `ngx_http_request_body_t` 的 `request_body` 请求字段。该对象的字段 `bufs` 将结果保存为缓冲链。如果 [client_body_buffer_size](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_buffer_size) 指令指定的容量不足以在内存中容纳整个正文，则正文可以保存在内容缓冲区或文件缓冲区中。

下面的示例读取客户端请求正文并返回其大小。
```c
ngx_int_t
ngx_http_foo_content_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    rc = ngx_http_read_client_request_body(r, ngx_http_foo_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        /* error */
        return rc;
    }

    return NGX_DONE;
}


void
ngx_http_foo_init(ngx_http_request_t *r)
{
    off_t         len;
    ngx_buf_t    *b;
    ngx_int_t     rc;
    ngx_chain_t  *in, out;

    if (r->request_body == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    len = 0;

    for (in = r->request_body->bufs; in; in = in->next) {
        len += ngx_buf_size(in->buf);
    }

    b = ngx_create_temp_buf(r->pool, NGX_OFF_T_LEN);
    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    b->last = ngx_sprintf(b->pos, "%O", len);
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    out.buf = b;
    out.next = NULL;

    rc = ngx_http_output_filter(r, &out);

    ngx_http_finalize_request(r, rc);
}
```
请求的以下字段确定如何读取请求正文：

- request_body_in_single_buf - 将正文读取到单个内存缓冲区。
- request_body_in_file_only - 始终将正文读取到文件中，即使它适合内存缓冲区。
- request_body_in_persistent_file - 创建文件后不要立即取消链接。具有此标志的文件可以移动到另一个目录。
- request_body_in_clean_file - 请求完成后取消文件链接。当文件应该被移动到另一个目录但由于某种原因没有移动时，这可能很有用。
- request_body_file_group_access - 通过将默认的 0600 访问掩码替换为 0660，启用对文件的组访问。
- request_body_file_log_level - 记录文件错误的严重级别。
- request_body_no_buffering - 读取请求正文，不带缓冲。

`request_body_no_buffering` 标志启用读取请求主体的无缓冲模式。在这种模式下，调用 `ngx_http_read_client_request_body()` 后，`bufs` 链可能只保留主体的一部分。要读取下一部分，请调用 `ngx_http_read_unbuffered_request_body(r)` 函数。返回值 `NGX_AGAIN` 和请求标志 `reading_body` 指示更多数据可用。如果调用此函数后 `bufs` 为 NULL，则此时没有任何可读取的内容。请求回调 `read_event_handler` 将在请求正文的下一部分可用时被调用。

## 请求体过滤器
读取请求主体部分后，通过调用存储在 `ngx_http_top_request_body_filter` 变量中的第一个主体过滤处理程序，将其传递给请求主体过滤器链。假设每个主体处理程序都会调用链中的下一个处理程序，直到最后一个处理程序 `ngx_http_request_body_save_filter(r, cl)` 被调用。此处理程序收集 `r->request_body->bufs` 中的缓冲区，并在必要时将其写入文件。最后一个请求主体缓冲区具有非零 `last_buf` 标志。

如果过滤器计划延迟数据缓冲区，则在第一次调用时，应将标志 `r->request_body->filter_need_buffering` 设置为 1。

以下是一个简单的请求正文过滤器的示例，它将请求正文延迟一秒。
```c
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_DELAY_BODY  1000


typedef struct {
    ngx_event_t   event;
    ngx_chain_t  *out;
} ngx_http_delay_body_ctx_t;


static ngx_int_t ngx_http_delay_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static void ngx_http_delay_body_cleanup(void *data);
static void ngx_http_delay_body_event_handler(ngx_event_t *ev);
static ngx_int_t ngx_http_delay_body_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_delay_body_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_delay_body_init,      /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};


ngx_module_t  ngx_http_delay_body_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_delay_body_module_ctx, /* module context */
    NULL,                          /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_request_body_filter_pt   ngx_http_next_request_body_filter;


static ngx_int_t
ngx_http_delay_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                   rc;
    ngx_chain_t                *cl, *ln;
    ngx_http_cleanup_t         *cln;
    ngx_http_delay_body_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "delay request body filter");

    ctx = ngx_http_get_module_ctx(r, ngx_http_delay_body_filter_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_delay_body_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_delay_body_filter_module);

        r->request_body->filter_need_buffering = 1;
    }

    if (ngx_chain_add_copy(r->pool, &ctx->out, in) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!ctx->event.timedout) {
        if (!ctx->event.timer_set) {

            /* cleanup to remove the timer in case of abnormal termination */

            cln = ngx_http_cleanup_add(r, 0);
            if (cln == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            cln->handler = ngx_http_delay_body_cleanup;
            cln->data = ctx;

            /* add timer */

            ctx->event.handler = ngx_http_delay_body_event_handler;
            ctx->event.data = r;
            ctx->event.log = r->connection->log;

            ngx_add_timer(&ctx->event, NGX_HTTP_DELAY_BODY);
        }

        return ngx_http_next_request_body_filter(r, NULL);
    }

    rc = ngx_http_next_request_body_filter(r, ctx->out);

    for (cl = ctx->out; cl; /* void */) {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);
    }

    ctx->out = NULL;

    return rc;
}


static void
ngx_http_delay_body_cleanup(void *data)
{
    ngx_http_delay_body_ctx_t *ctx = data;

    if (ctx->event.timer_set) {
        ngx_del_timer(&ctx->event);
    }
}


static void
ngx_http_delay_body_event_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "delay request body event");

    ngx_post_event(c->read, &ngx_posted_events);
}


static ngx_int_t
ngx_http_delay_body_init(ngx_conf_t *cf)
{
    ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter = ngx_http_delay_body_filter;

    return NGX_OK;
}
```

## 响应
在 nginx 中，HTTP 响应是通过发送响应头和可选的响应主体来生成的。header 和 body 都通过一系列过滤器传递，并最终写入客户端套接字。nginx 模块可以将其处理程序安装到 header 或 body 过滤器链中，并处理来自前一个处理程序的输出。

## 响应头
`ngx_http_send_header(r)` 函数发送输出报头。在 `r->headers_out` 包含生成 HTTP 响应头所需的所有数据之前，不要调用此函数。必须始终设置 `r->headers_out` 中的 `status` 字段。如果响应状态指示响应主体跟随在报头之后，也可以设置 `content_length_n`。此字段的默认值为 `-1`，这意味着主体大小未知。在这种情况下，使用分块传输编码。要输出任意的头，请附加 `headers` 列表。
```c
static ngx_int_t
ngx_http_foo_content_handler(ngx_http_request_t *r)
{
    ngx_int_t         rc;
    ngx_table_elt_t  *h;

    /* send header */

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 3;

    /* X-Foo: foo */

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "X-Foo");
    ngx_str_set(&h->value, "foo");

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    /* send body */

    ...
}
```

## 报头过滤器
`ngx_http_send_header(r)` 函数通过调用存储在 `ngx_http_top_header_filter` 变量中的第一个头过滤器处理程序来调用头过滤器。假设每个头处理程序都调用链中的下一个处理程序，直到最后一个处理程序 `ngx_http_header_filter(r)` 被调用。最后一个头处理程序基于 `r->headers_out` 构造 HTTP 响应，并将其传递给 `ngx_http_writer_filter` 进行输出。

要将处理程序添加到头过滤器链，请在配置时将其地址存储在全局变量 `ngx_http_top_header_filter` 中。以前的处理程序地址通常存储在模块的静态变量中，并在退出之前由新添加的处理程序调用。

下面的头过滤器模块示例将 HTTP 头 "X-Foo: foo" 添加到状态为 200 的每个响应。
```c
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_foo_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_foo_header_filter_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_foo_header_filter_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_foo_header_filter_init,        /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};


ngx_module_t  ngx_http_foo_header_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_foo_header_filter_module_ctx, /* module context */
    NULL,                                   /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_int_t
ngx_http_foo_header_filter(ngx_http_request_t *r)
{
    ngx_table_elt_t  *h;

    /*
     * The filter handler adds "X-Foo: foo" header
     * to every HTTP 200 response
     */

    if (r->headers_out.status != NGX_HTTP_OK) {
        return ngx_http_next_header_filter(r);
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "X-Foo");
    ngx_str_set(&h->value, "foo");

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_foo_header_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_foo_header_filter;

    return NGX_OK;
}
```

## 响应体
要发送响应体，请调用 `ngx_http_output_filter(r, cl)` 函数。函数可以多次调用。每次，它都会以缓冲链的形式发送响应体的一部分。在最后一个主体缓冲区中设置 `last_buf` 标志。

下面的示例生成了一个完整的 HTTP 响应，其中包含 "foo" 作为其正文。为了使示例既可以作为子请求也可以作为主请求工作，在输出的最后一个缓冲区中设置 `last_in_chain` 标志。`last_buf` 标志仅为主请求设置，因为子请求的最后一个缓冲区不会结束整个输出。
```c
static ngx_int_t
ngx_http_bar_content_handler(ngx_http_request_t *r)
{
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t   out;

    /* send header */

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 3;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    /* send body */

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    b->memory = 1;

    b->pos = (u_char *) "foo";
    b->last = b->pos + 3;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}
```

## 响应体过滤器
函数 `ngx_http_output_filter(r, cl)` 通过调用存储在 `ngx_http_top_body_filter` 变量中的第一个主体过滤器处理程序来调用主体过滤器链。假设每个主体过滤处理程序都会调用链中的下一个处理程序，直到最后一个处理程序 `ngx_http_write_filter(r, cl)` 被调用。

主体过滤器处理程序接收缓冲区链。处理程序应该处理缓冲区，并将可能的新链传递给下一个处理程序。值得注意的是，传入链节 `ngx_chain_t` 属于调用者，不能重用或更改。处理程序完成后，调用方可以使用其输出链节来跟踪发送的缓冲区。为了保存缓冲区链或在传递到下一个过滤器之前替换一些缓冲区，处理程序需要分配自己的链节。

下面是一个简单的正文过滤器的示例，它计算正文中的字节数。结果作为 `$counter` 变量可用，可在访问日志中使用。
```c
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    off_t  count;
} ngx_http_counter_filter_ctx_t;


static ngx_int_t ngx_http_counter_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_counter_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_counter_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_counter_filter_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_counter_filter_module_ctx = {
    ngx_http_counter_add_variables,        /* preconfiguration */
    ngx_http_counter_filter_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_counter_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_counter_filter_module_ctx,   /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_body_filter_pt  ngx_http_next_body_filter;

static ngx_str_t  ngx_http_counter_name = ngx_string("counter");


static ngx_int_t
ngx_http_counter_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_chain_t                    *cl;
    ngx_http_counter_filter_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_counter_filter_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_counter_filter_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_counter_filter_module);
    }

    for (cl = in; cl; cl = cl->next) {
        ctx->count += ngx_buf_size(cl->buf);
    }

    return ngx_http_next_body_filter(r, in);
}


static ngx_int_t
ngx_http_counter_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    u_char                         *p;
    ngx_http_counter_filter_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_counter_filter_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;
    v->len = ngx_sprintf(p, "%O", ctx->count) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_counter_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_counter_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_counter_variable;

    return NGX_OK;
}


static ngx_int_t
ngx_http_counter_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_counter_body_filter;

    return NGX_OK;
}
```

## 构建过滤器模块
在编写主体或报头过滤器时，要特别注意过滤器在过滤器顺序中的位置。nginx 标准模块注册了许多报头和主体过滤器，重要的是在与它们相关的正确位置注册一个新的过滤器模块。通常，模块在其 postconfiguration 处理程序中注册过滤器。在处理过程中调用过滤器的顺序显然与注册它们的顺序相反。

对于第三方过滤器模块，nginx 提供了一个特殊的插槽 `HTTP_AUX_FILTER_MODULES`。要在此插槽中注册过滤器模块，请在模块配置中将 `ngx_module_type` 变量设置为 `HTTP_AUX_FILTER`。

下面的示例显示了一个过滤器模块配置文件，该文件假设模块只有一个源文件 `ngx_http_foo_filter_module.c`。
```shell
ngx_module_type=HTTP_AUX_FILTER
ngx_module_name=ngx_http_foo_filter_module
ngx_module_srcs="$ngx_addon_dir/ngx_http_foo_filter_module.c"

. auto/module
```

## 缓冲区复用
当发布或更改缓冲区流时，通常需要复用已分配的缓冲区。nginx 代码中一个标准且广泛采用的方法是为此保留两个缓冲链：`free` 和 `busy`。`free` 链保留所有的空闲缓冲区，这些缓冲区可以重复使用。`busy` 链保存当前模块发送的所有缓冲区，这些缓冲区仍在由其他过滤器处理程序使用。如果缓冲区的大小大于零，则认为其正在使用。通常，当缓冲区被过滤器消耗时，其 `pos` （对于文件缓冲区为 `file_pos`）会移向 `last` （对于文件缓冲区为 `file_last`）。一旦缓冲区被完全消耗，它就可以被重用了。要将新释放的缓冲区添加到 `free` 链，只需迭代 `busy` 链，并将其头部的零大小缓冲区移动到 `free` 就足够了。这个操作非常常见，所以有一个特殊的功能，`ngx_chain_update_chains(free, busy, out, tag)`。该函数将输出链 `out` 附加到 `busy`，并将空闲缓冲区从 `busy` 顶部移动到 `free`。只有具有指定 `tag` 的缓冲区被重用。这使得模块只重用它自己分配的缓冲区。

下面的示例是一个主体过滤器，它在每个传入缓冲区之前插入字符串 "foo"。如果可能的话，模块分配的新缓冲区将被重用。请注意，为了使本实例正常工作，还需要设置报头过滤器并将 `content_length_n` 重置为 -1，但此处不提供相关代码。
```c
typedef struct {
    ngx_chain_t  *free;
    ngx_chain_t  *busy;
}  ngx_http_foo_filter_ctx_t;


ngx_int_t
ngx_http_foo_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                   rc;
    ngx_buf_t                  *b;
    ngx_chain_t                *cl, *tl, *out, **ll;
    ngx_http_foo_filter_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_foo_filter_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_foo_filter_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_foo_filter_module);
    }

    /* create a new chain "out" from "in" with all the changes */

    ll = &out;

    for (cl = in; cl; cl = cl->next) {

        /* append "foo" in a reused buffer if possible */

        tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        b = tl->buf;
        b->tag = (ngx_buf_tag_t) &ngx_http_foo_filter_module;
        b->memory = 1;
        b->pos = (u_char *) "foo";
        b->last = b->pos + 3;

        *ll = tl;
        ll = &tl->next;

        /* append the next incoming buffer */

        tl = ngx_alloc_chain_link(r->pool);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        tl->buf = cl->buf;
        *ll = tl;
        ll = &tl->next;
    }

    *ll = NULL;

    /* send the new chain */

    rc = ngx_http_next_body_filter(r, out);

    /* update "busy" and "free" chains for reuse */

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_foo_filter_module);

    return rc;
}
```

## 负载均衡
[ngx_http_upstream_module](https://nginx.org/en/docs/http/ngx_http_upstream_module.html) 提供将请求传递到远程服务器所需的基本功能。实现特定协议（如 HTTP 或 FastCGI）的模块使用此功能。该模块还提供了一个用于创建自定义负载均衡模块的接口，并实现了默认的轮询方法。

[lest_conn ](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#least_conn)和 [hash](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#hash) 模块实现了替代的负载均衡方法，但实际上是作为上游轮询模块的扩展实现的，并且与之共享了很多代码，例如服务器组的表示。[keepalive](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#keepalive) 模块是扩展上游功能的独立模块。

[ngx_http_upstream_module](https://nginx.org/en/docs/http/ngx_http_upstream_module.html) 可以通过将相应的 [upstream](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#upstream) 块放置到配置文件中来显式配置，或者通过使用诸如 [proxy_pass](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass) 之类的指令来隐式配置，这些指令接受在服务器列表中的某个点被评估的 URL。其他负载均衡方法仅在明确的上游配置中可用。上游模块有自己的指令上下文 `NGX_HTTP_UPS_CONF`。结构定义如下：
```c
struct ngx_http_upstream_srv_conf_s {
    ngx_http_upstream_peer_t         peer;
    void                           **srv_conf;

    ngx_array_t                     *servers;  /* ngx_http_upstream_server_t */

    ngx_uint_t                       flags;
    ngx_str_t                        host;
    u_char                          *file_name;
    ngx_uint_t                       line;
    in_port_t                        port;
    ngx_uint_t                       no_port;  /* unsigned no_port:1 */

#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_shm_zone_t                  *shm_zone;
#endif
};
```

- srv_conf - upstream 模块的配置上下文。
- servers - `ngx_http_upstream_server_t` 的数组，解析 `upstream` 块中的一组[server](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#server) 指令的结果。
- flags - 主要标记负载均衡方法支持哪些特性的标志。这些功能被配置为 [server](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#server) 指令的参数：
   - NGX_HTTP_UPSTREAM_CREATE - 将显式定义的上游与通过 [proxy_pass](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass) 指令和 "friends" 自动创建的上游区分开来（FastCGI、SCGI 等）
   - NGX_HTTP_UPSTREAM_WEIGHT - 支持参数 `weight`
   - NGX_HTTP_UPSTREAM_MAX_FAILS - 支持参数 `max_fails`
   - NGX_HTTP_UPSTREAM_FAIL_TIMEOUT - 支持参数 `fail_timeout`
   - NGX_HTTP_UPSTREAM_DOWN - 支持参数 `down`
   - NGX_HTTP_UPSTREAM_BACKUP - 支持参数 `backup`
   - NGX_HTTP_UPSTREAM_MAX_CONNS - 支持参数 `max_conns`
- host - upstream 的名称。
- file_name, line - 配置文件和 `upstream` 块所在行的名称。
- port 和 no_port - 不用于显式定义的上游组。
- shm_zone - 此上游组使用的共享内存区域（如果有的话）。
- peer - 包含初始化上游配置的泛型方法的对象：
```c
typedef struct {
    ngx_http_upstream_init_pt        init_upstream;
    ngx_http_upstream_init_peer_pt   init;
    void                            *data;
} ngx_http_upstream_peer_t;
```
实现负载均衡算法的模块必须设置这些方法并初始化自己的 `data`。如果在配置解析期间没有初始化 `init_upstream`，`ngx_http_upstream_module` 将其设置为默认的 `ngx_http_upstream_init_round_robin` 算法。

   - init_upstream(cf, us) - 配置时方法，负责初始化一组服务器，成功后初始化 `init()` 方法。典型的负载均衡模块使用 `upstream` 块中的服务器列表来创建它们使用高效数据结构并将自己的配置保存到 `data` 字段。
   - init(r, us) - 初始化用于负载均衡的 per-request `ngx_http_upstream_perr_t.peer` 结构（不要与上面描述的 per-upstream 的 `ngx_http_upstream_srv_conf_t.peer` 混淆）。它作为 `data` 参数传递给所有处理服务器选择的回调。

当 nginx 必须将请求传递给另一台主机进行处理时，它会使用配置的负载均衡方法来获取要连接的地址。该方法是从类型 `ngx_peer_connection_t` 的 `ngx_http_upstream_t.peer` 对象获得的：
```c
struct ngx_peer_connection_s {
    ...

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    ngx_str_t                       *name;

    ngx_uint_t                       tries;

    ngx_event_get_peer_pt            get;
    ngx_event_free_peer_pt           free;
    ngx_event_notify_peer_pt         notify;
    void                            *data;

#if (NGX_SSL || NGX_COMPAT)
    ngx_event_set_peer_session_pt    set_session;
    ngx_event_save_peer_session_pt   save_session;
#endif

    ...
};
```
结构具有以下字段：

- sockaddr, socklen, name - 要连接的上游服务器地址；这是负载均衡方法的输出参数。
- data - 负载均衡方法的 per-request 数据；保持选择算法的状态，并且通常包括到上游配置的链路。它作为参数传递给所有处理服务器选择的方法（见下文）。
- tries - 允许连接到上游服务器的尝试[次数](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream_tries)。
- get, free, notify, set_session 和 save_session - 负载均衡模块的方法，如下所述。

所有方法至少接受两个参数：对等连接对象 `pc` 和由 `ngx_http_upstream_srv_conf_t.peer.init()` 创建的 `data`。请注意，由于负载均衡模块的“chaining"，它可能与 `pc.data` 不同。

- get(pc, data) - 当 upstream 模块准备好向上游服务器传递请求并需要知道其地址时调用的方法。该方法必须填充 `ngx_peer_connection_t` 结构的 `sockaddr`，`socklen` 和 `name` 字段。返回是以下之一：
   - NGX_OK - 已选择服务器。
   - NGX_ERROR - 发生内部错误
   - NGX_BUSY - 当前没有可用的服务器。这可能是由于许多原因造成的，包括：动态服务器组为空，组中的所有服务器都处于故障状态，或者组中的所有服务器都已处理最大数量的连接。
   - NGX_DONE - 底层连接已被重用，无需创建到上游服务器的新连接。此值由 `keepalive` 模块设置。
- free(pc, data, state) - 上游模块完成特定服务器的工作时调用的方法。`state` 参数是上游连接的完成状态，它是一个位掩码，此方法还递减 `tries` 计数器，具有以下可能值：
   - NGX_PEER_FAILED - 尝试不成功
   - NGX_PEER_NEXT - 当上游服务器返回代码 403 或 404 时的特殊情况，这不被认为是失败。
   - NGX_PEER_KEEPALIVE - 当前未使用
- notify(pc, data, type) - 目前在 OSS 版本中未使用。
- set_session(pc, data) 和 save_session(pc, data) - 特定于 SSL 的方法，用于将会话缓存到上游服务器。该实现由轮询均衡方法提供。

# 示例
[nginx-dev-examples](http://hg.nginx.org/nginx-dev-examples) 仓库提供了 nginx 模块示例。

# 代码风格

## 一般规则

- 最大文本宽度为 80 个字符
- 缩进为 4 个空格
- 没有制表符，没有尾随空格
- 同一行上的列表元素用空格分隔
- 十六进制文字是小写的
- 文件名、函数名和类型名以及全局变量具有 `ngx_` 或更特定的前缀，如 `ngx_http_` 和 `ngx_mail_`
```c
size_t
ngx_utf8_length(u_char *p, size_t n)
{
    u_char  c, *last;
    size_t  len;

    last = p + n;

    for (len = 0; p < last; len++) {

        c = *p;

        if (c < 0x80) {
            p++;
            continue;
        }

        if (ngx_utf8_decode(&p, last - p) > 0x10ffff) {
            /* invalid UTF-8 */
            return n;
        }
    }

    return len;
}
```

## 文件
典型的源文件可能包含以下部分，由两个空行分隔：

- 版权声明
- 头文件包含
- 预处理程序定义
- 类型定义
- 函数原型
- 变量定义
- 函数定义

版权声明看起来像这样：
```c
/*
 * Copyright (C) Author Name
 * Copyright (C) Organization, Inc.
 */
```
如果文件被显著修改，则应更新作者离了表，将新作者添加到顶部。

`ngx_config.h` 或 `ngx_core.h` 文件总是首先包含，然后是 `ngx_http.h`，`ngx_stream_h` 或 `ngx_mail.h` 中的一个。然后执行可选的外部头文件：
```c
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxslt/xslt.h>

#if (NGX_HAVE_EXSLT)
#include <libexslt/exslt.h>
#endif
```

头文件应该包括所谓的“头保护”：
```c
#ifndef _NGX_PROCESS_CYCLE_H_INCLUDED_
#define _NGX_PROCESS_CYCLE_H_INCLUDED_
...
#endif /* _NGX_PROCESS_CYCLE_H_INCLUDED_ */
```

## 注释

- 不使用 "//" 注释
- 文本是用英语写的，美国拼写是首选
- 多行注释的格式如下：
```c
/*
 * The red-black tree code is based on the algorithm described in
 * the "Introduction to Algorithms" by Cormen, Leiserson and Rivest.
 */
/* find the server configuration for the address:port */
```

## 预处理器
宏名称从 `ngx_` 或 `NGX_` （或更具体的）前缀开始。常量的宏名是大写的。参数化宏和初始值设定项的宏是小写的。宏名称和值至少由两个空格分隔：
```c
#define NGX_CONF_BUFFER  4096

#define ngx_buf_in_memory(b)  (b->temporary || b->memory || b->mmap)

#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))

#define ngx_null_string  { 0, NULL }
```
条件在括号内，否定在括号外：
```c
#if (NGX_HAVE_KQUEUE)
...
#elif ((NGX_HAVE_DEVPOLL && !(NGX_TEST_BUILD_DEVPOLL)) \
       || (NGX_HAVE_EVENTPORT && !(NGX_TEST_BUILD_EVENTPORT)))
...
#elif (NGX_HAVE_EPOLL && !(NGX_TEST_BUILD_EPOLL))
...
#elif (NGX_HAVE_POLL)
...
#else /* select */
...
#endif /* NGX_HAVE_KQUEUE */
```

## 类型
类型名称以 "_t" 后缀结尾。定义的类型名称至少由两个空格分隔：
```c
typedef ngx_uint_t  ngx_rbtree_key_t;
```
使用 `typedef` 定义结构类型。在结构内部，成员类型和名称是对齐的：
```c
typedef struct {
    size_t      len;
    u_char     *data;
} ngx_str_t;
```
保持文件中不同结构之间的对齐方式相同。指向自身的结构的名称以 "_s" 结尾。相邻的结构定义用两个空行分隔：
```c
typedef struct ngx_list_part_s  ngx_list_part_t;

struct ngx_list_part_s {
    void             *elts;
    ngx_uint_t        nelts;
    ngx_list_part_t  *next;
};


typedef struct {
    ngx_list_part_t  *last;
    ngx_list_part_t   part;
    size_t            size;
    ngx_uint_t        nalloc;
    ngx_pool_t       *pool;
} ngx_list_t;
```
每个结构成员都在自己的行中声明：
```c
typedef struct {
    ngx_uint_t        hash;
    ngx_str_t         key;
    ngx_str_t         value;
    u_char           *lowcase_key;
} ngx_table_elt_t;
```
结构中的函数指针定义以 "_pt" 结尾：
```c
typedef ssize_t (*ngx_recv_pt)(ngx_connection_t *c, u_char *buf, size_t size);
typedef ssize_t (*ngx_recv_chain_pt)(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);
typedef ssize_t (*ngx_send_pt)(ngx_connection_t *c, u_char *buf, size_t size);
typedef ngx_chain_t *(*ngx_send_chain_pt)(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);

typedef struct {
    ngx_recv_pt        recv;
    ngx_recv_chain_pt  recv_chain;
    ngx_recv_pt        udp_recv;
    ngx_send_pt        send;
    ngx_send_pt        udp_send;
    ngx_send_chain_pt  udp_send_chain;
    ngx_send_chain_pt  send_chain;
    ngx_uint_t         flags;
} ngx_os_io_t;
```
枚举的类型以 "_e" 结尾：
```c
typedef enum {
    ngx_http_fastcgi_st_version = 0,
    ngx_http_fastcgi_st_type,
    ...
    ngx_http_fastcgi_st_padding
} ngx_http_fastcgi_state_e;
```

## 变量
声明变量时先按照基类型的长度排序，然后按字母顺序排序。类型名和变量名对齐。类型和名称“列”用两个空格分隔。大数组放在声明块的末尾：
```c
u_char                      |  | *rv, *p;
ngx_conf_t                  |  | *cf;
ngx_uint_t                  |  |  i, j, k;
unsigned int                |  |  len;
struct sockaddr             |  | *sa;
const unsigned char         |  | *data;
ngx_peer_connection_t       |  | *pc;
ngx_http_core_srv_conf_t    |  |**cscfp;
ngx_http_upstream_srv_conf_t|  | *us, *uscf;
u_char                      |  |  text[NGX_SOCKADDR_STRLEN];
```
静态和全局变量可以在声明时初始化：
```c
static ngx_str_t  ngx_http_memcached_key = ngx_string("memcached_key");

static ngx_uint_t  mday[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

static uint32_t  ngx_crc32_table16[] = {
    0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
    ...
    0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
};
```
有一堆常用的类型/名称组合：
```c
u_char                        *rv;
ngx_int_t                      rc;
ngx_conf_t                    *cf;
ngx_connection_t              *c;
ngx_http_request_t            *r;
ngx_peer_connection_t         *pc;
ngx_http_upstream_srv_conf_t  *us, *uscf;
```

## 函数
所有的函数（即使是静态函数）都应该有原型。原型包括参数名。长原型在连续行上用单个缩进进行包装：
```c
static char *ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_init_phases(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);

static char *ngx_http_merge_servers(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf, ngx_http_module_t *module,
    ngx_uint_t ctx_index);
```
定义中的函数名以新行开始。函数体的左大括号位于不同的行上。函数体是缩进的。函数之间有两个空行：
```c
static ngx_int_t
ngx_http_find_virtual_server(ngx_http_request_t *r, u_char *host, size_t len)
{
    ...
}


static ngx_int_t
ngx_http_add_addresses(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_conf_port_t *port, ngx_http_listen_opt_t *lsopt)
{
    ...
}
```
函数名和左括号后面没有空格。长函数调用被包装，使得延续行从第一个函数参数的位置开始。如果不可能，请设置第一个延续行的格式，使其在位置 79 结束：
```c
ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               "http header: \"%V: %V\"",
               &h->key, &h->value);

hc->busy = ngx_palloc(r->connection->pool,
                  cscf->large_client_header_buffers.num * sizeof(ngx_buf_t *));
```
应该使用 `ngx_inline` 宏而不是 `inline`：
```c
static ngx_inline void ngx_cpuid(uint32_t i, uint32_t *buf);
```

## 表达式
除 "." 和 "->" 外的二元运算符应与其操作数分隔一个空格。一元运算符和下标与其操作数之间不使用空格分隔：
```c
width = width * 10 + (*fmt++ - '0');

ch = (u_char) ((decoded << 4) + (ch - '0'));

r->exten.data = &r->uri.data[i + 1];
```
类型转换与转换后的表达式之间用一个空格分隔。类型强制转换中的星号与类型名称之间用空格分隔：
```c
len = ngx_sock_ntop((struct sockaddr *) sin6, p, len, 1);
```
如果表达式不能放进一行，则将其换行。首选的换行点是二元运算符。继续行与表达式的开始对齐：
```c
if (status == NGX_HTTP_MOVED_PERMANENTLY
    || status == NGX_HTTP_MOVED_TEMPORARILY
    || status == NGX_HTTP_SEE_OTHER
    || status == NGX_HTTP_TEMPORARY_REDIRECT
    || status == NGX_HTTP_PERMANENT_REDIRECT)
{
    ...
}

p->temp_file->warn = "an upstream response is buffered "
                     "to a temporary file";
```
作为最后的手段，可以包装表达式，以便继续行在位置 79 结束：
```c
hinit->hash = ngx_pcalloc(hinit->pool, sizeof(ngx_hash_wildcard_t)
                                     + size * sizeof(ngx_hash_elt_t *));
```
上述规则也适用于子表达式，其中每个子表达式都有自己的缩进级别：
```c
if (((u->conf->cache_use_stale & NGX_HTTP_UPSTREAM_FT_UPDATING)
     || c->stale_updating) && !r->background
    && u->conf->cache_background_update)
{
    ...
}
```
有时，在强制转换后包装表达式比较方便。在这种情况下，继续行缩进：
```c
node = (ngx_rbtree_node_t *)
           ((u_char *) lr - offsetof(ngx_rbtree_node_t, color));
```
指针被显式地与 NULL（而不是 0）进行比较：
```c
if (ptr != NULL) {
    ...
}
```

## 条件句和循环
"if" 关键字与条件之间用一个空格分隔。大括号位于同一行上，或者如果条件占用太多航，则位于专用行上。闭合大括号位于专用线上，可选后跟 "else if /else "。通常，在 "else if / else " 部分之前有一个空行：
```c
if (node->left == sentinel) {
    temp = node->right;
    subst = node;

} else if (node->right == sentinel) {
    temp = node->left;
    subst = node;

} else {
    subst = ngx_rbtree_min(node->right, sentinel);

    if (subst->left != sentinel) {
        temp = subst->left;

    } else {
        temp = subst->right;
    }
}
```
类似的格式化规则应用于 "do" 和 "while" 循环：
```c
while (p < last && *p == ' ') {
    p++;
}

do {
    ctx->node = rn;
    ctx = ctx->next;
} while (ctx);
```
"switch" 关键字与条件之间用一个空格分隔。大括号位于同一条线上。闭合大括号位于专用线上。"case" 关键字与 "switch" 对齐：
```c
switch (ch) {
case '!':
    looked = 2;
    state = ssi_comment0_state;
    break;

case '<':
    copy_end = p;
    break;

default:
    copy_end = p;
    looked = 0;
    state = ssi_start_state;
    break;
}
```
大多数 "for"  循环的格式如下：
```c
for (i = 0; i < ccf->env.nelts; i++) {
    ...
}

for (q = ngx_queue_head(locations);
     q != ngx_queue_sentinel(locations);
     q = ngx_queue_next(q))
{
    ...
}
```
如果 "for" 语句的某个部分被省略，这由 " /* void */ " 注释指示：
```c
for (i = 0; /* void */ ; i++) {
    ...
}
```
一个空体的循环也可以用 " /* void */ " 注释来表示，它可以放在同一行上：
```c
for (cl = *busy; cl->next; cl = cl->next) { /* void */ }
```
一个无线循环看起来像这样：
```c
for ( ;; ) {
    ...
}
```

## 标签
标签用空行包围，并在上一级缩进：
```c
	if (i == 0) {
        u->err = "host not found";
        goto failed;
    }

    u->addrs = ngx_pcalloc(pool, i * sizeof(ngx_addr_t));
    if (u->addrs == NULL) {
        goto failed;
    }

    u->naddrs = i;

    ...

    return NGX_OK;

failed:

    freeaddrinfo(res);
    return NGX_ERROR;
```

## 调试内存问题
要调试内存问题（如缓冲区溢出或释放后使用错误），可以使用一些现代编译器支持的 [AddressSanitizer](https://en.wikipedia.org/wiki/AddressSanitizer)（ASan）。要使用 `gcc` 和 `clang` 启用 ASan，请使用 `-fsanitize=address` 编译器和链接器选项。在构建 nginx 时，这可以通过将选项添加到 `configure` 脚本的 `--with-cc-opt` 和 `--with-ld-opt` 参数来完成。

由于 nginx 中的大多数分配都是从 nginx 内部池进行的，因此启用 ASan 可能并不总是足以调试内存问题。内部池从系统中分配一大块内存，并从中削减较小的内存分配。但是，可以通过将 `NGX_DEBUG_PALLOC` 宏设置为 1 来禁用此机制。在这种情况下，分配直接传递给系统分配器，使其完全控制缓冲区边界。

下面的配置行总结了上面提供的信息。建议在不同平台上开发第三方模块和测试 nginx 时使用。
```shell
auto/configure --with-cc-opt='-fsanitize=address -DNGX_DEBUG_PALLOC=1'
               --with-ld-opt=-fsanitize=address
```

# 常见陷阱

## 编写 C 模块
最常见的陷阱是试图在可以避免的情况下编写一个完整的 C 模块。在大多数情况下，您的任务可以通过创建适当的配置来完成。如果编写一个模块是不可避免的，那么尽量使它尽可能的小和简单。例如，模块只能导出某些[变量](https://nginx.org/en/docs/dev/development_guide.html#http_variables)。

在启动模块之前，请考虑以下问题：

- 是否可以使用[现有的模块](https://nginx.org/en/docs/index.html)实现所需的功能？
- 是否可以使用内置脚本语言（如 [Perl](https://nginx.org/en/docs/http/ngx_http_perl_module.html) 或 [njs](https://nginx.org/en/docs/njs/index.html)）解决问题？

## C 字符串
nginx 中最常用的字符串类型，[ngx_str_t](https://nginx.org/en/docs/dev/development_guide.html#string_overview) 不是 C 风格的零终止字符串。您不能将数据传递给标准 C 库函数，如 `strlen()` 或 `strstr()`。相反，应该使用接受 `ngx_str_t` 或指向数据和长度的指针的 nginx [对应项](https://nginx.org/en/docs/dev/development_guide.html#string_overview)。然而，当 `ngx_str_t` 持有一个指向以零结尾的字符串的指针时，由一种情况：作为配置文件解析结果的字符串以零结尾。

## 全局变量
避免在模块中使用全局变量。最有可能的是，这是一个错误，有一个全局变量。任何全局变量都应该绑定到一个[配置周期](https://nginx.org/en/docs/dev/development_guide.html#cycle)，并从响应的[内存池](https://nginx.org/en/docs/dev/development_guide.html#pool)中分配。这允许 nginx 执行优雅的配置重新加载。尝试使用全局变量可能会破坏此功能，因为不可能同时拥有两个配置并拜托它们。有时需要全局变量。在这种情况下，需要特别注意正确地管理重新配置。另外，检查代码使用的库是否具有可能在重新加载时被破坏的隐式全局状态。

## 手动管理内存
学习如何使用 nginx [池](https://nginx.org/en/docs/dev/development_guide.html#pool)而不是处理容易出错的 malloc/free 方法。创建池并将其绑定到对象 - [配置](https://nginx.org/en/docs/dev/development_guide.html#http_conf)、[周期](https://nginx.org/en/docs/dev/development_guide.html#cycle)、[连接](https://nginx.org/en/docs/dev/development_guide.html#connection)或 [HTTP 请求](https://nginx.org/en/docs/dev/development_guide.html#http_request)。当对象被销毁时，关联的池也被销毁。因此，当使用对象时，可以从相应的池中分配所需的量，即使在错误的情况下也不关心内存释放。

## 线程
建议避免在 nginx 中使用线程，因为它肯定会破坏东西：大多数 nginx 函数不是线程安全的。预期线程将仅执行系统调用和线程安全库函数。如果你需要运行一些与客户端请求处理无关的代码，正确的方法是在 `init_process` 模块处理程序中调度一个计时器，并在计时器处理程序中执行所需的操作。在内部，nginx 使用[线程](https://nginx.org/en/docs/dev/development_guide.html#threads)来增强与 IO 相关的操作，但这是一个有很多限制的特殊情况。

## 阻塞库
一个常见的错误是使用内部阻塞的库。大多数库本质上都是同步和阻塞的。换句话说，它们一次执行一个操作，并浪费时间等待其他对等体的响应。因此，当使用这样的库处理请求时，整个 nginx worker 被阻塞，从而破坏性能。只使用提供异步接口的库，不要阻塞整个进程。

## 对外部服务的 HTTP 请求
通常，模块需要对某些外部服务执行 HTTP 调用。一个常见的错误是使用一些外部库（如 libcurl）来执行 HTTP 请求。绝对没有必要带着巨大的外部（可能是阻塞！）代码去完成可以由 nginx 自己完成的任务。

当需要外部请求时，有两种基本的使用场景：

- 在处理客户端请求的上下文中（例如，在内容处理程序中）
- 在工作进程的上下文中（例如，计时器处理程序）

在第一种情况下，最好使用 [subrequests API](https://nginx.org/en/docs/dev/development_guide.html#http_subrequests)。与直接访问外部服务不同，你在 nginx 配置中声明一个位置，并将你的子请求定向到这个位置。此位置不限于[代理](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass)请求，但可能包含其他 nginx 指令。这种方法的一个示例是在 [ngx_http_auth_request](http://hg.nginx.org/nginx/file/tip/src/http/modules/ngx_http_auth_request_module.c) 模块中实现的 [auth_request](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html#auth_request) 指令。

对于第二种情况，可以使用 nginx 中提供的基本 HTTP 客户端功能。例如，[OCSP 模块](http://hg.nginx.org/nginx/file/tip/src/event/ngx_event_openssl_stapling.c)实现了简单的 HTTP 客户端。
