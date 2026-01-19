/**
 * @authoer:zhaolinhuang create:2012-12-5
 */
Date.prototype.format = function (formatString) {
    var that = this;
    var formatMapper = {
        "%Y": this.getFullYear(),
        "%m": this.getMonth() + 1,
        "%d": this.getDate(),
        "%H": this.getHours(),
        "%M": this.getMinutes(),
        // 英文的月份
        "%Em": this.toString().split(" ")[1],
        "%s": this.getSeconds(),
        "%S": this.getMilliseconds(),
        "%w": this.getDay(),
        "%U": (function (day) {
            return {
                0: "周日",
                1: "周一",
                2: "周二",
                3: "周三",
                4: "周四",
                5: "周五",
                6: "周六"
            }[day];
        })(this.getDay()),
        "%u": function () {
            return parseInt(((that.getTime() - new Date(that.format("%Y-01-01")).getTime()) / (1000 * 24 * 60 * 60) + 1) / 7) + 1;
        }
    };
    if (formatString) {
        try {
            for (var d in formatMapper) {
                var re = new RegExp(d, 'g');
                formatString = formatString.replace(
                    re, (String(formatMapper[d]).length == 1 ? ("0" + formatMapper[d]) : formatMapper[d]));
            }
        } catch (e) {
            console.log("FORMAT DATE ERROR:" + e);
        }
    }
    return formatString;
};
/**
 * sleep秒级
 */
Date.prototype.sleep = function (millSecond) {
    var nowTime = new Date().getTime();
    var compareTime = nowTime + millSecond;
    while (new Date().getTime() < compareTime) {

    }
    return;
};
/**
 * 如:2012年12月18日 00:00
 */
Date.prototype.datetime2FullCN = function () {
    return this.format("%Y年%m月%d日 %H:%M");
};
/**
 * 如:2012-12-18 00:00
 */
Date.prototype.datetime2FullMin = function () {
    return this.format("%Y-%m-%d %H:%M");
};

/**
 *
 * @returns {*}
 */
Date.prototype.datetime2SimpleFormat = function () {
    return this.format("%Y-%m-%d %H:%M:%s");
};
/**
 * 时区 ，东：+，西：-
 */
Date.prototype.changeTimezone = function (timeZone) {
    var times = this.getTime();
    var EnglandTime = times + this.getTimezoneOffset() * 60 * 1000;
    var yourTimeZoneTime = EnglandTime + timeZone * 60 * 60 * 1000;
    this.setTime(yourTimeZoneTime);
    return this;
};
/**
 * 秒级
 *
 * @param second
 */
Date.prototype.changeTime = function (second) {
    var nowTime = this.getTime();
    this.setTime(nowTime + second * 1000);
    return this;
};
/**
 * 加天数，可以为负数
 *
 * @param dayNum
 */
Date.prototype.addDays = function (dayNum) {
    var times = dayNum * 24 * 60 * 60 * 1000;
    this.setTime(this.getTime() + times);
    return this;
};
/**
 * 毫秒级时间对比
 * -1 小于
 * 0 等于
 * 1 大于
 */
Date.prototype.compareTime = function (compareDate) {
    if (compareDate instanceof Date) {
        if (compareDate.getTime() > this.getTime()) {
            return -1;
        } else if (compareDate.getTime() == this.getTime()) {
            return 0;
        } else {
            return 1;
        }
    } else {
        throw {
            name: "传入参数异常",
            message: compareDate + "不是正确的Date对象"
        };
    }
};
/**
 * 只比较日期
 *
 * @param compareDate
 */
Date.prototype.compareDay = function (compareDate) {
    if (compareDate instanceof Date) {
        var thisDate = new Date(this.format("%Y-%m-%d 00:00:00"));
        compareDate = new Date(compareDate.format("%Y-%m-%d 00:00:00"));
        return thisDate.compareTime(compareDate);
    } else {
        throw {
            name: "传入参数异常",
            message: compareDate + "不是正确的Date对象"
        }
    }
};
/**
 * format的结果转成Date对象
 */
Date.prototype.formatReturnDate = function (formatString) {
    try {
        return new Date(this.format(formatString));
    } catch (e) {
        console.log(e)
    }
};


