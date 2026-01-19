package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"gitlab.alibaba-inc.com/fengjin.hf/g53"
	"go.uber.org/zap"

	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/cache"
	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/logger"
	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/metrics"
)

const (
	MetricsPath = "/metrics"

	ListMessageCachePath = "/ListMessageCache"
	ListRRsetCachePath   = "/ListRRsetCache"
)

func Run(addr string, msgCache *cache.Cache, m *metrics.Metrics) {
	gin.SetMode(gin.ReleaseMode)
	g := gin.New()
	g.GET(MetricsPath, m.HttpHandler())
	g.POST(ListMessageCachePath, func(ctx *gin.Context) {
		name := ctx.PostForm("name")
		typ := ctx.PostForm("type")
		qname, err := g53.NameFromString(name)
		if err != nil {
			responseError(ctx, fmt.Sprintf("invalid name:%s", err.Error()))
			return
		}

		qtype, err := g53.TypeFromString(typ)
		if err != nil {
			responseError(ctx, fmt.Sprintf("invalid type:%s", err.Error()))
			return
		}

		resp := msgCache.Get(g53.NewRequestBuilder(qname, qtype).Done())
		if resp != nil {
			responseSuccess(ctx, map[string]interface{}{"message": resp.String()})
		} else {
			responseSuccess(ctx, map[string]interface{}{"message": ""})
		}
	})

	g.POST(ListRRsetCachePath, func(ctx *gin.Context) {
		name := ctx.PostForm("name")
		typ := ctx.PostForm("type")
		qname, err := g53.NameFromString(name)
		if err != nil {
			responseError(ctx, fmt.Sprintf("invalid name:%s", err.Error()))
			return
		}

		qtype, err := g53.TypeFromString(typ)
		if err != nil {
			responseError(ctx, fmt.Sprintf("invalid type:%s", err.Error()))
			return
		}

		rrset := msgCache.GetRRset(qname, qtype)
		if rrset != nil {
			responseSuccess(ctx, map[string]interface{}{"rrset": rrset.String()})
		} else {
			responseSuccess(ctx, map[string]interface{}{"rrset": ""})
		}
	})

	if err := g.Run(addr); err != nil {
		logger.GetLogger().Fatal("run cmd server failed", zap.Error(err))
	}
}

func responseError(ctx *gin.Context, errMsg string) {
	ctx.JSON(http.StatusUnprocessableEntity, gin.H{
		"errorMessage": errMsg,
	})
}

func responseSuccess(ctx *gin.Context, response map[string]interface{}) {
	ctx.JSON(http.StatusOK, gin.H(response))
}
