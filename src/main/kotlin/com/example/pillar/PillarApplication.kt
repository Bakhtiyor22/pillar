package com.example.pillar

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class PillarApplication

fun main(args: Array<String>) {
	runApplication<PillarApplication>(*args)
}